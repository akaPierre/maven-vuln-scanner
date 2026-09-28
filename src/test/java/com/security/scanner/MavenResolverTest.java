package com.security.scanner;

import com.security.model.Dependency;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MavenResolverTest {

    @Test
    void parsesDependencyListOutput() {
        List<Dependency> deps = MavenResolver.parseDependencyList(List.of(
                "",
                "The following files have been resolved:",
                "   com.google.code.gson:gson:jar:2.10.1:compile -- module com.google.gson",
                "   org.junit.jupiter:junit-jupiter-api:jar:5.10.0:test -- module org.junit.jupiter.api",
                "   io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100.Final:runtime",
                "   org.example:optional-lib:jar:1.0:compile (optional)",
                "",
                "The following files have been resolved:",
                "   com.google.code.gson:gson:jar:2.10.1:compile -- module com.google.gson",
                "   none"));

        assertEquals(List.of(
                new Dependency("com.google.code.gson", "gson", "2.10.1", "compile"),
                new Dependency("org.junit.jupiter", "junit-jupiter-api", "5.10.0", "test"),
                new Dependency("io.netty", "netty-transport-native-epoll", "4.1.100.Final", "runtime"),
                new Dependency("org.example", "optional-lib", "1.0", "compile")
        ), deps);
    }
}
