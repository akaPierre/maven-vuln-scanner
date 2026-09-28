package com.security.scanner;

import com.security.model.Dependency;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Resolves the full dependency graph (including transitive dependencies and versions
 * managed by remote parents/BOMs) by running {@code mvn dependency:list}.
 */
public final class MavenResolver {

    private static final String DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:list";
    private static final long TIMEOUT_MINUTES = 15;

    private MavenResolver() {
    }

    public static List<Dependency> resolve(File pomFile) throws IOException, InterruptedException {
        File pom = pomFile.getAbsoluteFile();
        Path output = Files.createTempFile("mvnscan-deps", ".txt");
        Path log = Files.createTempFile("mvnscan-mvn", ".log");
        try {
            List<String> command = new ArrayList<>();
            command.add(mavenExecutable(pom.getParentFile()));
            command.addAll(List.of(
                    "-B", "-q",
                    "-f", pom.getPath(),
                    DEPENDENCY_PLUGIN,
                    "-DoutputFile=" + output,
                    "-DappendOutput=true",
                    "-DoutputAbsoluteArtifactFilename=false"));

            Process process = new ProcessBuilder(command)
                    .directory(pom.getParentFile())
                    .redirectErrorStream(true)
                    .redirectOutput(log.toFile())
                    .start();

            if (!process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                throw new IOException("Maven dependency resolution timed out");
            }
            if (process.exitValue() != 0) {
                String mavenLog = Files.readString(log, StandardCharsets.UTF_8);
                throw new IOException("Maven dependency resolution failed (exit " + process.exitValue() + "):\n"
                        + tail(mavenLog, 30));
            }
            return parseDependencyList(Files.readAllLines(output, StandardCharsets.UTF_8));
        } finally {
            Files.deleteIfExists(output);
            Files.deleteIfExists(log);
        }
    }

    /**
     * Parses lines such as {@code   com.google.code.gson:gson:jar:2.10.1:compile -- module com.google.gson}.
     * Multi-module builds append one section per module, so duplicates are removed.
     */
    static List<Dependency> parseDependencyList(List<String> lines) {
        Map<String, Dependency> deps = new LinkedHashMap<>();
        for (String line : lines) {
            String coords = line.strip();
            int moduleInfo = coords.indexOf(" -- ");
            if (moduleInfo >= 0) {
                coords = coords.substring(0, moduleInfo);
            }
            // Strip trailing annotations like "(optional)"
            int space = coords.indexOf(' ');
            if (space >= 0) {
                coords = coords.substring(0, space);
            }

            String[] parts = coords.split(":");
            // groupId:artifactId:type:version:scope or groupId:artifactId:type:classifier:version:scope
            if (parts.length != 5 && parts.length != 6) {
                continue;
            }
            String version = parts[parts.length - 2];
            String scope = parts[parts.length - 1];
            Dependency dep = new Dependency(parts[0], parts[1], version, scope);
            deps.putIfAbsent(dep.toString(), dep);
        }
        return new ArrayList<>(deps.values());
    }

    /** Prefers the project's Maven wrapper so the build uses the Maven version it expects. */
    private static String mavenExecutable(File projectDir) {
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        File dir = projectDir;
        while (dir != null) {
            File wrapper = new File(dir, windows ? "mvnw.cmd" : "mvnw");
            if (wrapper.isFile() && (windows || wrapper.canExecute())) {
                return wrapper.getAbsolutePath();
            }
            dir = dir.getParentFile();
        }
        return windows ? "mvn.cmd" : "mvn";
    }

    private static String tail(String text, int lines) {
        List<String> all = text.lines().toList();
        return String.join("\n", all.subList(Math.max(0, all.size() - lines), all.size()));
    }
}
