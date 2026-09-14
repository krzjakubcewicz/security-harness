package com.example.securityharness.autonomy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VersionChangeTest {

    @Test
    void aChangedFirstSegmentIsMajor() {
        assertEquals(VersionChange.MAJOR, VersionChange.between("1.30", "2.0"));
        assertEquals(VersionChange.MAJOR, VersionChange.between("2.0.0", "3.1.4"));
    }

    @Test
    void aChangedSecondSegmentIsMinor() {
        assertEquals(VersionChange.MINOR, VersionChange.between("1.30", "1.31"));
    }

    @Test
    void aChangedThirdSegmentIsPatch() {
        assertEquals(VersionChange.PATCH, VersionChange.between("3.2.1", "3.2.2"));
    }

    @Test
    void aMissingThirdSegmentReadsAsZero() {
        assertEquals(VersionChange.NONE, VersionChange.between("2.0", "2.0.0"));
        assertEquals(VersionChange.PATCH, VersionChange.between("2.0", "2.0.1"));
    }

    @Test
    void theSameVersionIsNoChange() {
        assertEquals(VersionChange.NONE, VersionChange.between("3.2.1", "3.2.1"));
    }

    @Test
    void aDowngradeIsStillTheLevelThatDiffers() {
        // Direction is not the question a gate asks; how far the version moved is.
        assertEquals(VersionChange.MAJOR, VersionChange.between("2.0.0", "1.9.9"));
    }

    @Test
    void anythingThatIsNotSemverIsUnknown() {
        assertEquals(VersionChange.UNKNOWN, VersionChange.between("3.2.1", null));
        assertEquals(VersionChange.UNKNOWN, VersionChange.between(null, "2.0"));
        assertEquals(VersionChange.UNKNOWN, VersionChange.between("3.2.1", "commons-collections4"));
        assertEquals(VersionChange.UNKNOWN, VersionChange.between("", "2.0"));
    }

    @Test
    void aQualifierAfterThePatchSegmentIsIgnored() {
        assertEquals(VersionChange.MINOR, VersionChange.between("2.7.18", "2.8.0-RC1"));
    }

    @Test
    void anAbsurdlyLongNumberIsUnknownRatherThanAnOverflow() {
        assertEquals(VersionChange.UNKNOWN, VersionChange.between("1.0.0", "99999999999.0.0"));
    }
}
