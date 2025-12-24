package com.security.scanner;

import com.google.gson.Gson;
import com.security.model.Dependency;
import com.security.model.Vulnerability;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(name = "mvnscan", mixinStandardHelpOptions = true, version = "mvnscan 1.0")
public class ScannerApp implements Callable<Integer> {
    @Parameters(index = "0", description = "Path to pom.xml")
    private File pomFile;

    @Option(names = {"-j", "--json"}, description = "JSON output for CI")
    private boolean json;

    @Option(names = {"-s", "--summary"}, description = "Show only critical/high vulns")
    private boolean summary;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ScannerApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        if (!pomFile.exists()) {
            System.err.println("❌ File not found: " + pomFile.getAbsolutePath());
            return 1;
        }

        System.out.println("🔍 Scanning " + pomFile.getName() + "...");
        List<Dependency> deps = PomParser.parsePom(pomFile);
        System.out.println("📦 Found " + deps.size() + " dependencies");

        OssIndexClient client = new OssIndexClient();
        List<Vulnerability> vulns = client.checkDependencies(deps);

        if (json) {
            Gson gson = new Gson();
            System.out.println(gson.toJson(vulns));
        } else if (vulns.isEmpty()) {
            System.out.println("✅ No known vulnerabilities found!");
        } else {
            printReport(vulns);
        }

        return vulns.isEmpty() ? 0 : 1;
    }

    private void printReport(List<Vulnerability> vulns) {
        Set<Vulnerability> uniqueVulns = vulns.stream()
                .collect(Collectors.toSet());

        long critical = uniqueVulns.stream()
                .filter(v -> "CRITICAL".equals(v.severity()))
                .count();

        System.out.printf("🚨 Found %d unique vulnerabilities (%d critical)%n%n",
                uniqueVulns.size(), critical);

        uniqueVulns.forEach(v ->
                System.out.printf("  %s - %s [%s] (CVSS: %s)%n",
                        v.id(), v.title(), v.severity(), v.cvssScore())
        );
    }
}