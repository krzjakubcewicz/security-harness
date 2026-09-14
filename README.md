# Security Harness

Remediates vulnerability findings one service at a time: updates a dependency or hands the
finding to an agent, verifies the change, runs the build, then decides what to do with the
result. Design and workflow: [DESIGN.md](DESIGN.md).

## Requirements

- Java 21+
- Maven 3.9+
- Git — each service directory must be a clean Git repo (or pass `--no-verify-changes`)
- Whatever the service's stack needs to build (`mvn` for Java, `pip`/`pytest` for Python)

## Build

```bash
mvn package
```

Produces `target/security-harness-1.0-SNAPSHOT.jar` (executable, dependencies shaded in).

## Run

```bash
java -jar target/security-harness-1.0-SNAPSHOT.jar \
  --vulnerabilities /path/to/findings.json \
  --repos /path/to/repos \
  --output /path/to/output
```

### Flags

| Flag | Required | Meaning |
| --- | --- | --- |
| `--vulnerabilities <path>` | yes | Scanner findings JSON. |
| `--repos <dir>` | no | Root holding one directory per service. Defaults to the current directory. |
| `--output <dir>` | no | Write a run report here. No flag, no report. |
| `--no-verify-changes` | no | Skip the clean-tree requirement and the Git-vs-write-ledger check. Testing only. |

### Layout

Each finding's `service` field names a directory under `--repos`:

```
repos/
  inventory-api/   pom.xml        <- java stack
  report-worker/   pyproject.toml <- python stack
```

A service with no directory is marked `NEEDS_ATTENTION` and skipped.

### Findings file

```json
{
  "findings": [
    {
      "id": "F-40219",
      "cve": "CVE-2020-14343",
      "severity": "high",
      "service": "report-worker",
      "package": "PyYAML",
      "installed_version": "5.3.1",
      "path": "direct",
      "fixed_version": "5.4"
    }
  ]
}
```

`path: "direct"` takes the deterministic version-update route; anything else goes to the agent.
`fixed_version: null` on a direct finding means manual attention — nothing is attempted.
Working example: `examples/findings-agent.json`.

## Configuration

Three YAML files on the classpath, `src/main/resources/`:

| File | Controls |
| --- | --- |
| `build-gate.yaml` | Per-stack marker file, dependency file, build output dirs, ordered build/test steps. |
| `guards.yaml` | What agent tool calls get routed to manual review. No match means allow. |
| `autonomy.yaml` | What happens to the changes: `auto_merge`, `pull_request`, `slack`, `jira`, `none`. No match means `pull_request`. Empty list turns the feature off. |

Edit and rebuild. Each file documents its own matching rules in comments.

## Output

- Console: per-finding trace, then a per-service summary.
- `--output <dir>`: `run-<UTC timestamp>.json` with the full run, including what aborted it.

Exit code `0` when every finding is `SUCCESS`, `1` otherwise (needs attention, or the run aborted).

## Agent

The agent is `MockLlmStub` — deterministic, no network, no API key. Answers come from
`src/main/resources/llm-responses/<CVE>.json`. A CVE with no such file produces no tool calls.
New scenario = new resource file.

## Tests

```bash
mvn test
```

`SecurityHarnessCliE2ETest` runs the real CLI end to end over `examples/findings-agent.json`.

## TODO

- **Handle missing `fixedVersion`** — Route findings without `fixedVersion` to the agent instead of manual review. The agent should use the CVE and `pom.xml` or other files to resolve the vulnerability and create a PR if needed.

- **Support repository-specific YAML configuration** — Keep global `guards.yaml`, `autonomy.yaml`, and `build-gate.yaml` built into the Harness. Repository-level YAML files may only add extra requirements; they must not override global configuration.

- **Validate repository YAMLs** — Check repository YAML files for explicit attempts to bypass, weaken, or compromise global Harness configuration. Trigger an alert if such an attempt is detected.

- **Alert on guard violations** — If the agent attempts to access files or directories outside the allowed scope, trigger a Slack alert and prevent the agent from running.

- **Verify vulnerability remediation** — Add a step within the existing verification phase that uses an external vulnerability detector to confirm that the targeted vulnerabilities have actually been resolved, before actions such as creating a pull request.
