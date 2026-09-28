# Maven Vulnerability Scanner 🚨

CLI tool that scans Maven `pom.xml` files for dependencies with known vulnerabilities (CVEs / GitHub
Security Advisories), using the free [OSV.dev](https://osv.dev) database. No API key required.

## Features
- ✅ Parses dependencies from `pom.xml`, resolving `${properties}`, `<dependencyManagement>` and local parent poms
- ✅ `--resolve` mode runs Maven to include **transitive** dependencies and BOM-managed versions
- ✅ Real vulnerability data from OSV (GitHub Advisory Database, NVD, ...)
- ✅ CVSS v3 base scores computed from the advisory vectors, with severity ratings
- ✅ Shows the version that fixes each issue
- ✅ JSON output for CI/CD pipelines, with configurable failure threshold
- ✅ Fails loudly (exit code 2) when the lookup fails, so a network error never looks like a clean scan
- ✅ Hardened XML parsing (no XXE) for scanning untrusted poms

## Usage
```
mvnscan <pom.xml>                    # Human-readable report of direct dependencies
mvnscan pom.xml --resolve            # Include transitive dependencies (runs mvn)
mvnscan pom.xml --json               # JSON for CI
mvnscan pom.xml --summary            # Show only critical/high
mvnscan pom.xml --fail-on HIGH       # Exit 1 only for HIGH or CRITICAL findings
mvnscan pom.xml --include-test       # Also scan test-scoped dependencies
mvnscan --help                       # Full help
```

### Exit codes
| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities at or above the `--fail-on` threshold (default: any) |
| 1 | Vulnerabilities found at or above the threshold |
| 2 | Scan error: invalid pom, Maven failure, or OSV unreachable |

### Direct vs. transitive scanning
Without `--resolve`, only dependencies declared in the pom (and its local parents) are checked, and
versions that come from a remote parent or an imported BOM (e.g. Spring Boot starters) are listed as
skipped. Use `--resolve` for complete results. It runs `mvn dependency:list` (or the project's
`mvnw`), so it needs Maven installed and should only be used on projects you trust, since Maven
can execute build extensions declared in the pom.

## Example
```
$ mvnscan my-project/pom.xml
🔍 Scanning my-project/pom.xml...
📦 Found 12 dependencies to check
🚨 Found 3 vulnerabilities in 2 dependencies (critical: 3, high: 0, medium: 0, low: 0, unknown: 0)

📦 org.apache.logging.log4j:log4j-core:2.14.1
   [CRITICAL 10.0] CVE-2021-44228 - Remote code injection in Log4j
       fixed in 2.15.0 | https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q
   [CRITICAL 9.0] CVE-2021-45046 - Incomplete fix for Apache Log4j vulnerability
       fixed in 2.16.0 | https://osv.dev/vulnerability/GHSA-7rjr-3q55-vv33

📦 com.h2database:h2:1.4.200
   [CRITICAL 9.8] CVE-2021-42392 - RCE in H2 Console
       fixed in 2.0.206 | https://osv.dev/vulnerability/GHSA-h376-j262-vhq6
```

### JSON output
```json
{
  "pom": "pom.xml",
  "scannedDependencies": 12,
  "skippedDependencies": [],
  "counts": { "UNKNOWN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 3 },
  "vulnerabilities": [
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "title": "Remote code injection in Log4j",
      "severity": "CRITICAL",
      "cvssScore": 10.0,
      "dependency": "org.apache.logging.log4j:log4j-core:2.14.1",
      "fixedVersions": ["2.15.0"],
      "url": "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"
    }
  ]
}
```
Progress messages go to stderr, so `stdout` contains only the JSON document.

## CI/CD Integration
Fail a GitHub Actions build on high or critical vulnerabilities:
```yaml
- run: mvn -B clean package
- run: java -jar target/mvnscan.jar pom.xml --resolve --json --fail-on HIGH > scan.json
```
See [`.github/workflows/maven-scan.yml`](.github/workflows/maven-scan.yml) for a full example that
also uploads the report.

## Installation
```
mvn clean package
java -jar target/mvnscan.jar --help
```

**Built with:** Java 17, Picocli, Gson, `java.net.http`. Vulnerability data by [OSV.dev](https://osv.dev).
