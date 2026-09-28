package com.security.scanner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.security.model.Dependency;
import com.security.model.Severity;
import com.security.model.Vulnerability;
import com.security.model.osv.OsvBatchResponse;
import com.security.model.osv.OsvVulnerability;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Looks up known vulnerabilities in the OSV database (https://osv.dev), which aggregates
 * GitHub Security Advisories, NVD CVEs and others for the Maven ecosystem.
 */
public class OsvClient {

    public static final String DEFAULT_BASE_URL = "https://api.osv.dev";

    /** OSV accepts at most 1000 queries per batch request. */
    private static final int BATCH_SIZE = 1000;
    private static final int MAX_ATTEMPTS = 4;
    private static final int DETAIL_THREADS = 8;

    private final String baseUrl;
    private final HttpClient http;
    private final Gson gson = new Gson();

    public OsvClient() {
        this(DEFAULT_BASE_URL);
    }

    public OsvClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Returns every known vulnerability affecting the given dependencies.
     *
     * @throws IOException if OSV can't be reached. Failing loudly matters here: silently
     *                     returning nothing would report a vulnerable project as clean.
     */
    public List<Vulnerability> checkDependencies(List<Dependency> deps) throws IOException, InterruptedException {
        Map<Dependency, Set<String>> idsByDependency = queryIds(deps);

        Set<String> uniqueIds = new LinkedHashSet<>();
        idsByDependency.values().forEach(uniqueIds::addAll);
        Map<String, OsvVulnerability> details = fetchDetails(uniqueIds);

        List<Vulnerability> result = new ArrayList<>();
        idsByDependency.forEach((dep, ids) -> {
            for (String id : ids) {
                result.add(toVulnerability(dep, details.get(id)));
            }
        });
        return result;
    }

    private Map<Dependency, Set<String>> queryIds(List<Dependency> deps) throws IOException, InterruptedException {
        Map<Dependency, Set<String>> ids = new LinkedHashMap<>();
        List<Dependency> pending = new ArrayList<>(deps);
        Map<Dependency, String> pageTokens = new HashMap<>();

        // Results are paginated per query; keep re-querying dependencies that returned a page token
        while (!pending.isEmpty()) {
            List<Dependency> nextRound = new ArrayList<>();
            for (int start = 0; start < pending.size(); start += BATCH_SIZE) {
                List<Dependency> batch = pending.subList(start, Math.min(start + BATCH_SIZE, pending.size()));
                OsvBatchResponse response = gson.fromJson(
                        post("/v1/querybatch", batchRequest(batch, pageTokens)), OsvBatchResponse.class);
                if (response == null || response.results == null || response.results.size() != batch.size()) {
                    throw new IOException("Unexpected response from OSV querybatch");
                }

                for (int i = 0; i < batch.size(); i++) {
                    Dependency dep = batch.get(i);
                    OsvBatchResponse.Result r = response.results.get(i);
                    Set<String> depIds = ids.computeIfAbsent(dep, d -> new LinkedHashSet<>());
                    if (r.vulns != null) {
                        r.vulns.forEach(v -> depIds.add(v.id));
                    }
                    if (r.nextPageToken != null && !r.nextPageToken.isEmpty()) {
                        pageTokens.put(dep, r.nextPageToken);
                        nextRound.add(dep);
                    } else {
                        pageTokens.remove(dep);
                    }
                }
            }
            pending = nextRound;
        }
        return ids;
    }

    private String batchRequest(List<Dependency> batch, Map<Dependency, String> pageTokens) {
        JsonArray queries = new JsonArray();
        for (Dependency dep : batch) {
            JsonObject pkg = new JsonObject();
            pkg.addProperty("ecosystem", "Maven");
            pkg.addProperty("name", dep.packageName());

            JsonObject query = new JsonObject();
            query.add("package", pkg);
            query.addProperty("version", dep.version());
            String token = pageTokens.get(dep);
            if (token != null) {
                query.addProperty("page_token", token);
            }
            queries.add(query);
        }
        JsonObject body = new JsonObject();
        body.add("queries", queries);
        return gson.toJson(body);
    }

    private Map<String, OsvVulnerability> fetchDetails(Set<String> ids) throws IOException, InterruptedException {
        Map<String, OsvVulnerability> details = new HashMap<>();
        if (ids.isEmpty()) {
            return details;
        }

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(DETAIL_THREADS, ids.size()));
        try {
            Map<String, Future<OsvVulnerability>> futures = new LinkedHashMap<>();
            for (String id : ids) {
                String path = "/v1/vulns/" + URLEncoder.encode(id, StandardCharsets.UTF_8);
                futures.put(id, pool.submit(() -> gson.fromJson(get(path), OsvVulnerability.class)));
            }
            for (Map.Entry<String, Future<OsvVulnerability>> entry : futures.entrySet()) {
                details.put(entry.getKey(), entry.getValue().get());
            }
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException("Failed to fetch vulnerability details: " + cause.getMessage(), cause);
        } finally {
            pool.shutdownNow();
        }
        return details;
    }

    private String post(String path, String json) throws IOException, InterruptedException {
        return send(requestBuilder(path)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build());
    }

    private String get(String path) throws IOException, InterruptedException {
        return send(requestBuilder(path).GET().build());
    }

    private HttpRequest.Builder requestBuilder(String path) {
        return HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(30))
                .header("User-Agent", "mvnscan/1.0")
                .header("Accept", "application/json");
    }

    /** Sends with retries and exponential backoff on network errors, 429 and 5xx responses. */
    private String send(HttpRequest request) throws IOException, InterruptedException {
        IOException lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                int status = response.statusCode();
                if (status >= 200 && status < 300) {
                    return response.body();
                }
                lastError = new IOException("OSV returned HTTP " + status + " for " + request.uri());
                if (status != 429 && status < 500) {
                    throw lastError;
                }
            } catch (IOException e) {
                if (e == lastError) {
                    throw e;
                }
                lastError = e;
            }
            if (attempt < MAX_ATTEMPTS) {
                Thread.sleep(500L * (1L << (attempt - 1)));
            }
        }
        throw lastError;
    }

    static Vulnerability toVulnerability(Dependency dep, OsvVulnerability osv) {
        Double score = null;
        Severity severity = Severity.UNKNOWN;

        if (osv.severity != null) {
            for (OsvVulnerability.Severity s : osv.severity) {
                if ("CVSS_V3".equals(s.type)) {
                    OptionalDouble parsed = CvssV3.baseScore(s.score);
                    if (parsed.isPresent()) {
                        score = parsed.getAsDouble();
                        severity = Severity.fromScore(score);
                        break;
                    }
                }
            }
        }
        // Fall back to the advisory's own rating, e.g. when only a CVSS v4 vector is published
        if (severity == Severity.UNKNOWN && osv.databaseSpecific != null) {
            severity = Severity.fromLabel(osv.databaseSpecific.severity);
        }

        return new Vulnerability(
                osv.id,
                osv.aliases != null ? List.copyOf(osv.aliases) : List.of(),
                title(osv),
                severity,
                score,
                dep.toString(),
                fixedVersions(dep, osv),
                "https://osv.dev/vulnerability/" + osv.id);
    }

    private static String title(OsvVulnerability osv) {
        if (osv.summary != null && !osv.summary.isBlank()) {
            return osv.summary.trim();
        }
        if (osv.details != null && !osv.details.isBlank()) {
            String firstLine = osv.details.strip().lines().findFirst().orElse("");
            return firstLine.length() > 120 ? firstLine.substring(0, 117) + "..." : firstLine;
        }
        return "No description available";
    }

    private static List<String> fixedVersions(Dependency dep, OsvVulnerability osv) {
        Set<String> fixed = new LinkedHashSet<>();
        if (osv.affected == null) {
            return List.of();
        }
        for (OsvVulnerability.Affected affected : osv.affected) {
            if (affected.pkg == null || !dep.packageName().equals(affected.pkg.name) || affected.ranges == null) {
                continue;
            }
            for (OsvVulnerability.Range range : affected.ranges) {
                if (range.events == null) {
                    continue;
                }
                for (Map<String, String> event : range.events) {
                    String version = event.get("fixed");
                    if (version != null) {
                        fixed.add(version);
                    }
                }
            }
        }
        // Advisories list fixes for every maintained branch; only upgrades are useful to the user
        List<String> upgrades = fixed.stream()
                .filter(v -> compareVersions(v, dep.version()) > 0)
                .sorted(OsvClient::compareVersions)
                .toList();
        return upgrades.isEmpty() ? List.copyOf(fixed) : upgrades;
    }

    /** Simplified Maven version ordering: numeric segments compare numerically, others lexically. */
    static int compareVersions(String a, String b) {
        String[] pa = a.split("[.\\-]");
        String[] pb = b.split("[.\\-]");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            String sa = i < pa.length ? pa[i] : "0";
            String sb = i < pb.length ? pb[i] : "0";
            boolean na = sa.chars().allMatch(Character::isDigit) && !sa.isEmpty();
            boolean nb = sb.chars().allMatch(Character::isDigit) && !sb.isEmpty();
            int cmp;
            if (na && nb) {
                cmp = new BigInteger(sa).compareTo(new BigInteger(sb));
            } else if (na != nb) {
                // "1.0" > "1.0-beta": a number outranks a qualifier
                cmp = na ? 1 : -1;
            } else {
                cmp = sa.compareToIgnoreCase(sb);
            }
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }
}
