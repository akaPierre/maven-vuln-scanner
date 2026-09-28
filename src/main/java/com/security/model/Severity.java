package com.security.model;

import java.util.Locale;

/** Severity levels ordered from least to most severe. */
public enum Severity {
    UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL;

    /** Maps a CVSS base score to a qualitative rating (CVSS v3 specification, section 5). */
    public static Severity fromScore(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return UNKNOWN;
    }

    /** Parses labels used by advisory databases, e.g. GitHub's "MODERATE". */
    public static Severity fromLabel(String label) {
        if (label == null) return UNKNOWN;
        return switch (label.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> CRITICAL;
            case "HIGH" -> HIGH;
            case "MEDIUM", "MODERATE" -> MEDIUM;
            case "LOW" -> LOW;
            default -> UNKNOWN;
        };
    }

    public boolean isAtLeast(Severity other) {
        return compareTo(other) >= 0;
    }
}
