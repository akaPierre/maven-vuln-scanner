package com.security.scanner;

import java.util.HashMap;
import java.util.Map;
import java.util.OptionalDouble;

/**
 * Computes CVSS v3.0 / v3.1 base scores from vector strings such as
 * {@code CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}.
 * Formulas from https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
 */
public final class CvssV3 {

    private CvssV3() {
    }

    public static OptionalDouble baseScore(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3.")) {
            return OptionalDouble.empty();
        }

        Map<String, String> metrics = new HashMap<>();
        for (String part : vector.split("/")) {
            String[] kv = part.split(":", 2);
            if (kv.length == 2) {
                metrics.put(kv[0], kv[1]);
            }
        }

        try {
            boolean scopeChanged = "C".equals(require(metrics, "S"));

            double av = switch (require(metrics, "AV")) {
                case "N" -> 0.85;
                case "A" -> 0.62;
                case "L" -> 0.55;
                case "P" -> 0.2;
                default -> throw new IllegalArgumentException("AV");
            };
            double ac = switch (require(metrics, "AC")) {
                case "L" -> 0.77;
                case "H" -> 0.44;
                default -> throw new IllegalArgumentException("AC");
            };
            double pr = switch (require(metrics, "PR")) {
                case "N" -> 0.85;
                case "L" -> scopeChanged ? 0.68 : 0.62;
                case "H" -> scopeChanged ? 0.5 : 0.27;
                default -> throw new IllegalArgumentException("PR");
            };
            double ui = switch (require(metrics, "UI")) {
                case "N" -> 0.85;
                case "R" -> 0.62;
                default -> throw new IllegalArgumentException("UI");
            };
            double c = cia(require(metrics, "C"));
            double i = cia(require(metrics, "I"));
            double a = cia(require(metrics, "A"));

            double iss = 1 - ((1 - c) * (1 - i) * (1 - a));
            double impact = scopeChanged
                    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
                    : 6.42 * iss;
            double exploitability = 8.22 * av * ac * pr * ui;

            if (impact <= 0) {
                return OptionalDouble.of(0.0);
            }
            double score = scopeChanged
                    ? roundUp(Math.min(1.08 * (impact + exploitability), 10))
                    : roundUp(Math.min(impact + exploitability, 10));
            return OptionalDouble.of(score);
        } catch (IllegalArgumentException e) {
            return OptionalDouble.empty();
        }
    }

    private static String require(Map<String, String> metrics, String key) {
        String value = metrics.get(key);
        if (value == null) {
            throw new IllegalArgumentException(key);
        }
        return value;
    }

    private static double cia(String value) {
        return switch (value) {
            case "H" -> 0.56;
            case "L" -> 0.22;
            case "N" -> 0.0;
            default -> throw new IllegalArgumentException(value);
        };
    }

    /** The "Roundup" function from CVSS v3.1 Appendix A, which avoids floating point surprises. */
    private static double roundUp(double value) {
        long intInput = Math.round(value * 100_000);
        if (intInput % 10_000 == 0) {
            return intInput / 100_000.0;
        }
        return (Math.floor(intInput / 10_000.0) + 1) / 10.0;
    }
}
