package com.security.scanner;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.security.model.Dependency;
import com.security.model.Severity;
import com.security.model.Vulnerability;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OsvClientTest {

    private HttpServer server;
    private OsvClient client;
    private final Map<String, String> vulnDetails = new ConcurrentHashMap<>();
    private final AtomicInteger batchCalls = new AtomicInteger();

    private static final Dependency H2 = new Dependency("com.h2database", "h2", "1.4.200", "compile");
    private static final Dependency GSON = new Dependency("com.google.code.gson", "gson", "2.8.8", "compile");
    private static final Dependency CLEAN = new Dependency("org.example", "clean", "1.0", "compile");

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/querybatch", this::handleBatch);
        server.createContext("/v1/vulns/", exchange -> {
            String id = exchange.getRequestURI().getPath().substring("/v1/vulns/".length());
            String body = vulnDetails.get(id);
            respond(exchange, body == null ? 404 : 200, body == null ? "{}" : body);
        });
        server.start();
        client = new OsvClient("http://127.0.0.1:" + server.getAddress().getPort());

        vulnDetails.put("GHSA-h376-j262-vhq6", """
                {
                  "id": "GHSA-h376-j262-vhq6",
                  "summary": "RCE in H2 Console",
                  "aliases": ["CVE-2021-42392"],
                  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                  "affected": [{
                    "package": {"ecosystem": "Maven", "name": "com.h2database:h2"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.1.100"}, {"fixed": "2.0.206"}]}]
                  }],
                  "database_specific": {"severity": "CRITICAL"}
                }
                """);
        vulnDetails.put("GHSA-second-page", """
                {
                  "id": "GHSA-second-page",
                  "details": "Issue only described in details.\\nMore text.",
                  "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}],
                  "database_specific": {"severity": "MODERATE"}
                }
                """);
        vulnDetails.put("GHSA-4jrv-ppp4-jm57", """
                {
                  "id": "GHSA-4jrv-ppp4-jm57",
                  "summary": "Deserialization of Untrusted Data in Gson",
                  "aliases": ["CVE-2022-25647"],
                  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                  "affected": [{
                    "package": {"ecosystem": "Maven", "name": "com.google.code.gson:gson"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.8.9"}]}]
                  }]
                }
                """);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    /** Returns vulns by package name; h2 results are split across two pages. */
    private void handleBatch(HttpExchange exchange) throws IOException {
        batchCalls.incrementAndGet();
        JsonObject request = JsonParser.parseString(
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();

        StringBuilder results = new StringBuilder();
        for (var element : request.getAsJsonArray("queries")) {
            JsonObject query = element.getAsJsonObject();
            String name = query.getAsJsonObject("package").get("name").getAsString();
            boolean secondPage = query.has("page_token");
            String result = switch (name) {
                case "com.h2database:h2" -> secondPage
                        ? "{\"vulns\":[{\"id\":\"GHSA-second-page\"}]}"
                        : "{\"vulns\":[{\"id\":\"GHSA-h376-j262-vhq6\"}],\"next_page_token\":\"page2\"}";
                case "com.google.code.gson:gson" -> "{\"vulns\":[{\"id\":\"GHSA-4jrv-ppp4-jm57\"}]}";
                default -> "{}";
            };
            results.append(results.length() == 0 ? "" : ",").append(result);
        }
        respond(exchange, 200, "{\"results\":[" + results + "]}");
    }

    @Test
    void mapsOsvAdvisoriesToVulnerabilities() throws Exception {
        List<Vulnerability> vulns = client.checkDependencies(List.of(H2, GSON, CLEAN));

        Map<String, Vulnerability> byId = vulns.stream()
                .collect(Collectors.toMap(Vulnerability::id, Function.identity()));
        assertEquals(3, vulns.size());
        assertEquals(2, batchCalls.get(), "second call fetches h2's next page");

        Vulnerability h2 = byId.get("GHSA-h376-j262-vhq6");
        assertEquals("CVE-2021-42392", h2.displayId());
        assertEquals(Severity.CRITICAL, h2.severity());
        assertEquals(9.8, h2.cvssScore());
        assertEquals("com.h2database:h2:1.4.200", h2.dependency());
        assertEquals(List.of("2.0.206"), h2.fixedVersions());
        assertEquals("https://osv.dev/vulnerability/GHSA-h376-j262-vhq6", h2.url());

        Vulnerability v4Only = byId.get("GHSA-second-page");
        assertEquals(Severity.MEDIUM, v4Only.severity(), "falls back to the advisory's MODERATE rating");
        assertNull(v4Only.cvssScore());
        assertEquals("Issue only described in details.", v4Only.title());
        assertEquals("GHSA-second-page", v4Only.displayId());

        Vulnerability gson = byId.get("GHSA-4jrv-ppp4-jm57");
        assertEquals(Severity.HIGH, gson.severity());
        assertEquals(7.5, gson.cvssScore());
    }

    @Test
    void returnsNothingForEmptyInput() throws Exception {
        assertTrue(client.checkDependencies(List.of()).isEmpty());
        assertEquals(0, batchCalls.get());
    }

    @Test
    void failsInsteadOfReportingCleanWhenApiErrors() {
        server.removeContext("/v1/querybatch");
        server.createContext("/v1/querybatch", exchange -> respond(exchange, 400, "{\"message\":\"bad\"}"));

        IOException e = assertThrows(IOException.class, () -> client.checkDependencies(List.of(H2)));
        assertTrue(e.getMessage().contains("HTTP 400"), e.getMessage());
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
