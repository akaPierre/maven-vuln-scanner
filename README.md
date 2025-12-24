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

## MIT License

Copyright (c) 2025 Daniel Pierre Fachini de Toledo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

**Built with:** Java 17, Picocli, OkHttp, Gson
