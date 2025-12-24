# Maven Vulnerability Scanner 🚨

CLI tool that scans Maven `pom.xml` files for known vulnerabilities with professional output.

## Features
- ✅ Parses Maven dependencies from `pom.xml`
- ✅ Detects CVEs with severity/CVSS scores
- ✅ Deduplicated unique vulnerability reports
- ✅ JSON output for CI/CD pipelines
- ✅ Zero-exit on clean, non-zero on vulns

## Usage
- `mvnscan <pom.xml> # Human-readable report`
- `mvnscan pom.xml --json # JSON for CI`
- `mvnscan pom.xml --summary # Critical/High only`
- `mvnscan --help # Full help`

## Example
```
$ mvnscan my-project/pom.xml
🔍 Scanning pom.xml...
📦 Found 12 dependencies
🚨 Found 3 unique vulnerabilities (1 critical)

CVE-2022-22965 - Spring4Shell RCE [CRITICAL] (CVSS: 9.8)
CVE-2023-20862 - Spring Expression Bypass [HIGH] (CVSS: 7.5)
```

## CI/CD Integration
Fails build on critical vulnerabilities:

- run: ./mvnw mvnscan pom.xml
- if: failure()
- run: echo "🚨 Security scan failed - fix vulnerabilities!"

## Installation
```
mvn clean package
java -jar target/maven-vuln-scanner-1.0-SNAPSHOT.jar --help
```

**Built with:** Java 17, Picocli, OkHttp, Gson