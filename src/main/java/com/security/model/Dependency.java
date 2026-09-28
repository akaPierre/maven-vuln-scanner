package com.security.model;

public record Dependency(String groupId, String artifactId, String version, String scope) {

    /** Package name in the format OSV expects for the Maven ecosystem: {@code groupId:artifactId}. */
    public String packageName() {
        return groupId + ":" + artifactId;
    }

    public boolean hasResolvedVersion() {
        return version != null && !version.isBlank() && !version.contains("${");
    }

    @Override
    public String toString() {
        return packageName() + ":" + version;
    }
}
