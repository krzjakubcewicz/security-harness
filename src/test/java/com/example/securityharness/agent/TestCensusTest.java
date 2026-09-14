package com.example.securityharness.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TestCensusTest {

    // --- Java: what declares a test -------------------------------------------------------

    @Test
    void junitAnnotationsEachDeclareATest() {
        assertEquals(2, TestCensus.liveIn("""
                class OrderServiceTest {
                    @Test
                    void a() {
                    }

                    @ParameterizedTest
                    @ValueSource(ints = {1, 2})
                    void b(int n) {
                    }
                }
                """));
    }

    @Test
    void anAnnotationIndentedWithTabsStillCounts() {
        assertEquals(1, TestCensus.liveIn("class T {\n\t@Test\n\tvoid a() {\n\t}\n}\n"));
    }

    @Test
    void anAnnotationWithArgumentsCounts() {
        assertEquals(1, TestCensus.liveIn("@Test(timeout = 1)\nvoid a() {\n}\n"));
    }

    @Test
    void lifecycleAndClassLevelAnnotationsAreNotTests() {
        // @TestInstance and @BeforeEach decorate the class and the fixture, not a test. Counting
        // them would make an ordinary refactor look like it added tests.
        assertEquals(0, TestCensus.liveIn("""
                @TestInstance(Lifecycle.PER_CLASS)
                class OrderServiceTest {
                    @BeforeEach
                    void setUp() {
                    }
                }
                """));
    }

    // --- Java: what takes one away --------------------------------------------------------

    @Test
    void disabledAboveTheTestAnnotationSubtracts() {
        assertEquals(1, TestCensus.liveIn("""
                class T {
                    @Test
                    void a() {
                    }

                    @Disabled
                    @Test
                    void b() {
                    }
                }
                """));
    }

    @Test
    void disabledBelowTheTestAnnotationAlsoSubtracts() {
        // The whole contiguous run of annotations is one unit: order inside it is not a loophole.
        assertEquals(0, TestCensus.liveIn("@Test\n@Disabled\nvoid b() {\n}\n"));
    }

    @Test
    void aReasonStringDoesNotHideTheDisable() {
        assertEquals(0, TestCensus.liveIn("@Disabled(\"flaky on CI\")\n@Test\nvoid b() {\n}\n"));
    }

    @Test
    void junit4IgnoreCountsAsDisabled() {
        assertEquals(0, TestCensus.liveIn("@Ignore\n@Test\npublic void b() {\n}\n"));
    }

    /**
     * The cheapest way to empty a suite is one annotation on the class, so it has to count for
     * every test inside it rather than for the line it sits on.
     */
    @Test
    void aClassLevelDisableSilencesEveryTestInTheClass() {
        assertEquals(0, TestCensus.liveIn("""
                @Disabled
                class OrderServiceTest {
                    @Test
                    void a() {
                    }

                    @Test
                    void b() {
                    }

                    @Test
                    void c() {
                    }
                }
                """));
    }

    // --- Python: what declares a test -----------------------------------------------------

    @Test
    void moduleLevelPytestFunctionsEachCount() {
        assertEquals(3, TestCensus.liveIn("""
                def test_a():
                    assert True

                def test_b():
                    assert True

                def test_c():
                    assert True
                """));
    }

    @Test
    void methodsOfATestClassAreCountedWhereverTheyAreIndented() {
        assertEquals(2, TestCensus.liveIn("""
                class TestOrders(unittest.TestCase):
                    def test_a(self):
                        self.assertTrue(True)

                    def test_b(self):
                        self.assertTrue(True)
                """));
    }

    @Test
    void anAsyncTestCounts() {
        assertEquals(1, TestCensus.liveIn("async def test_a():\n    assert True\n"));
    }

    @Test
    void parametrizeDecoratesOneTestAndCountsOnce() {
        assertEquals(1, TestCensus.liveIn("""
                @pytest.mark.parametrize("n", [1, 2, 3])
                def test_a(n):
                    assert n
                """));
    }

    @Test
    void aHelperWhoseNameMerelyContainsTestIsNotATest() {
        assertEquals(0, TestCensus.liveIn("def helper_test(x):\n    return x\n"));
    }

    // --- Python: what takes one away ------------------------------------------------------

    @Test
    void everyPythonWayOfSilencingATestSubtracts() {
        assertEquals(0, TestCensus.liveIn("@pytest.mark.skip\ndef test_a():\n    assert True\n"));
        assertEquals(0, TestCensus.liveIn(
                "@pytest.mark.skipif(sys.version_info < (3, 9), reason=\"old\")\n"
                        + "def test_a():\n    assert True\n"));
        assertEquals(0, TestCensus.liveIn("@unittest.skip(\"why\")\ndef test_a(self):\n    pass\n"));
        assertEquals(0, TestCensus.liveIn("@skipUnless(HAS_DB, \"no db\")\ndef test_a(self):\n    pass\n"));
    }

    @Test
    void xfailSilencesARegressionJustAsCompletely() {
        // A test that runs but is expected to fail reports nothing when it starts failing.
        assertEquals(0, TestCensus.liveIn("@pytest.mark.xfail\ndef test_a():\n    assert True\n"));
    }

    @Test
    void aSkipStackedOnAParametrizeSubtractsThatOneAndNoMore() {
        assertEquals(1, TestCensus.liveIn("""
                @pytest.mark.parametrize("n", [1, 2, 3])
                @pytest.mark.skip
                def test_a(n):
                    assert n

                def test_b():
                    assert True
                """));
    }

    @Test
    void aSkippedClassSilencesItsMethodsAndNothingAfterIt() {
        // Indentation is how Python says "no longer inside": test_c is a module-level test and
        // survives a skip on the class above it.
        assertEquals(1, TestCensus.liveIn("""
                @pytest.mark.skip
                class TestOrders:
                    def test_a(self):
                        assert True

                    def test_b(self):
                        assert True

                def test_c():
                    assert True
                """));
    }

    // --- Neither --------------------------------------------------------------------------

    @Test
    void aFileWithNoTestsInItCountsZero() {
        assertEquals(0, TestCensus.liveIn("<project><artifactId>app</artifactId></project>\n"));
        assertEquals(0, TestCensus.liveIn("requests==2.31.0\npytest==8.0.0\n"));
        assertEquals(0, TestCensus.liveIn(""));
    }

    // --- across ---------------------------------------------------------------------------

    @Test
    void aFileThatDoesNotExistYetHasNoTests(@TempDir Path workDir) {
        Map<String, Integer> counts = new TestCensus(workDir)
                .across(List.of(new ToolCall("writeFile", "src/test/java/NewTest.java", "body")));

        assertEquals(Map.of("src/test/java/NewTest.java", 0), counts);
    }

    @Test
    void onePathNamedTwiceIsCountedOnce(@TempDir Path workDir) throws Exception {
        write(workDir, "OrderTest.java", "@Test\nvoid a() {\n}\n");

        Map<String, Integer> counts = new TestCensus(workDir).across(List.of(
                new ToolCall("writeFile", "OrderTest.java", "body"),
                new ToolCall("write", "OrderTest.java", "body")));

        assertEquals(Map.of("OrderTest.java", 1), counts);
    }

    @Test
    void aPolyglotResponseCountsBothFiles(@TempDir Path workDir) throws Exception {
        write(workDir, "OrderTest.java", "@Test\nvoid a() {\n}\n");
        write(workDir, "test_orders.py",
                "def test_a():\n    assert True\n\ndef test_b():\n    assert True\n");

        Map<String, Integer> counts = new TestCensus(workDir).across(List.of(
                new ToolCall("writeFile", "OrderTest.java", "body"),
                new ToolCall("writeFile", "test_orders.py", "body")));

        assertEquals(Map.of("OrderTest.java", 1, "test_orders.py", 2), counts);
        assertEquals(3, counts.values().stream().mapToInt(Integer::intValue).sum());
    }

    private static void write(Path workDir, String name, String content) throws Exception {
        Files.writeString(workDir.resolve(name), content, StandardCharsets.UTF_8);
    }
}
