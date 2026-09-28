package com.security.scanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.security.model.Dependency;
import com.security.model.Severity;
import com.security.model.Vulnerability;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(name = "mvnscan", mixinStandardHelpOptions = true, version = "mvnscan 1.0",
        description = "Scans a Maven pom.xml for dependencies with known vulnerabilities (via osv.dev).",
        exitCodeListHeading = "%nExit codes:%n",
        exitCodeList = {
                "0:No vulnerabilities at or above the --fail-on threshold",
                "1:Vulnerabilities found at or above the --fail-on threshold",
                "2:Scan error (bad pom, Maven or network failure)"})
public class ScannerApp implements Callable<Integer> {

    static final int EXIT_CLEAN = 0;
    static final int EXIT_VULNERABLE = 1;
    static final int EXIT_ERROR = 2;

    @Parameters(index = "0", description = "Path to pom.xml")
    private File pomFile;

    @Option(names = {"-j", "--json"}, description = "JSON output for CI")
    private boolean json;

    @Option(names = {"-s", "--summary"}, description = "Show only critical/high vulns")
    private boolean summary;

    @Option(names = {"-r", "--resolve"},
            description = "Run Maven to resolve transitive dependencies and BOM-managed versions. "
                    + "Only use on trusted projects: Maven may execute build extensions.")
    private boolean resolve;

    @Option(names = {"-t", "--include-test"}, description = "Also scan test-scoped dependencies")
    private boolean includeTest;

    @Option(names = "--fail-on", paramLabel = "<severity>", defaultValue = "UNKNOWN",
            description = "Exit with code 1 when a vulnerability at or above this severity is found: "
                    + "${COMPLETION-CANDIDATES} (default: any vulnerability)")
    private Severity failOn;

    @Option(names = "--no-fail", description = "Always exit 0 when the scan succeeds")
    private boolean noFail;

    @Option(names = "--osv-url", hidden = true, defaultValue = OsvClient.DEFAULT_BASE_URL)
    private String osvUrl;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ScannerApp())
                .setCaseInsensitiveEnumValuesAllowed(true)
                // Unexpected crashes must not look like "vulnerabilities found" (exit 1) to CI
                .setExecutionExceptionHandler((e, cmd, parseResult) -> {
                    cmd.getErr().println("❌ Scan failed: " + e);
                    return EXIT_ERROR;
                })
                .setParameterExceptionHandler((e, badArgs) -> {
                    e.getCommandLine().getErr().println(e.getMessage());
                    e.getCommandLine().usage(e.getCommandLine().getErr());
                    return EXIT_ERROR;
                })
                .execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        if (!pomFile.isFile()) {
            System.err.println("❌ File not found: " + pomFile.getAbsolutePath());
            return EXIT_ERROR;
        }

        // Progress goes to stderr so that --json output on stdout stays machine-readable
        System.err.println("🔍 Scanning " + pomFile.getPath() + (resolve ? " (resolving with Maven)" : "") + "...");

        List<Dependency> deps;
        try {
            deps = resolve ? MavenResolver.resolve(pomFile) : PomParser.parsePom(pomFile);
        } catch (IOException e) {
            System.err.println("❌ " + e.getMessage());
            return EXIT_ERROR;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return EXIT_ERROR;
        }

        List<Dependency> inScope = deps.stream()
                .filter(d -> includeTest || !"test".equals(d.scope()))
                .toList();
        List<Dependency> scannable = inScope.stream().filter(Dependency::hasResolvedVersion).toList();
        List<Dependency> unresolved = inScope.stream().filter(d -> !d.hasResolvedVersion()).toList();

        System.err.println("📦 Found " + scannable.size() + " dependencies to check");
        if (!unresolved.isEmpty()) {
            System.err.println("⚠️  Skipped " + unresolved.size() + " dependencies with unknown versions "
                    + "(managed by a remote parent or BOM; use --resolve):");
            unresolved.forEach(d -> System.err.println("     " + d.packageName()
                    + (d.version() == null || d.version().isBlank() ? "" : ":" + d.version())));
        }

        List<Vulnerability> vulns;
        try {
            vulns = new OsvClient(osvUrl).checkDependencies(scannable);
        } catch (IOException | UncheckedIOException e) {
            System.err.println("❌ Vulnerability lookup failed: " + e.getMessage());
            return EXIT_ERROR;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return EXIT_ERROR;
        }

        vulns = vulns.stream()
                .sorted(Comparator.comparing(Vulnerability::severity).reversed()
                        .thenComparing(v -> v.cvssScore() == null ? 0.0 : v.cvssScore(), Comparator.reverseOrder())
                        .thenComparing(Vulnerability::dependency))
                .toList();

        if (json) {
            printJson(scannable, unresolved, vulns);
        } else {
            printReport(vulns);
        }

        boolean failing = vulns.stream().anyMatch(v -> v.severity().isAtLeast(failOn));
        return failing && !noFail ? EXIT_VULNERABLE : EXIT_CLEAN;
    }

    private record JsonReport(String pom, int scannedDependencies, List<String> skippedDependencies,
                              Map<Severity, Long> counts, List<Vulnerability> vulnerabilities) {
    }

    private void printJson(List<Dependency> scanned, List<Dependency> skipped, List<Vulnerability> vulns) {
        List<Vulnerability> shown = summary ? filterSummary(vulns) : vulns;
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        System.out.println(gson.toJson(new JsonReport(
                pomFile.getPath(),
                scanned.size(),
                skipped.stream().map(Dependency::packageName).toList(),
                countBySeverity(vulns),
                shown)));
    }

    private void printReport(List<Vulnerability> vulns) {
        if (vulns.isEmpty()) {
            System.out.println("✅ No known vulnerabilities found!");
            return;
        }

        Map<Severity, Long> counts = countBySeverity(vulns);
        long affectedDeps = vulns.stream().map(Vulnerability::dependency).distinct().count();
        System.out.printf("🚨 Found %d vulnerabilities in %d dependencies (critical: %d, high: %d, medium: %d, low: %d, unknown: %d)%n",
                vulns.size(), affectedDeps,
                counts.get(Severity.CRITICAL), counts.get(Severity.HIGH), counts.get(Severity.MEDIUM),
                counts.get(Severity.LOW), counts.get(Severity.UNKNOWN));

        List<Vulnerability> shown = summary ? filterSummary(vulns) : vulns;
        if (summary && shown.size() < vulns.size()) {
            System.out.printf("   (showing critical/high only, %d hidden)%n", vulns.size() - shown.size());
        }

        Map<String, List<Vulnerability>> byDependency = shown.stream()
                .collect(Collectors.groupingBy(Vulnerability::dependency, LinkedHashMap::new, Collectors.toList()));

        byDependency.forEach((dependency, list) -> {
            System.out.println();
            System.out.println("📦 " + dependency);
            for (Vulnerability v : list) {
                String score = v.cvssScore() == null ? "" : String.format(" %.1f", v.cvssScore());
                System.out.printf("   [%s%s] %s - %s%n", v.severity(), score, v.displayId(), v.title());
                String fix = v.fixedVersions().isEmpty() ? "no fix available" : "fixed in " + String.join(", ", v.fixedVersions());
                System.out.printf("       %s | %s%n", fix, v.url());
            }
        });
    }

    private static List<Vulnerability> filterSummary(List<Vulnerability> vulns) {
        return vulns.stream().filter(v -> v.severity().isAtLeast(Severity.HIGH)).toList();
    }

    private static Map<Severity, Long> countBySeverity(List<Vulnerability> vulns) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, 0L);
        }
        vulns.forEach(v -> counts.merge(v.severity(), 1L, Long::sum));
        return counts;
    }
}
