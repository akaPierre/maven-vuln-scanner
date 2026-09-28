package com.security.scanner;

import com.security.model.Dependency;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PomParserTest {

    @TempDir
    Path dir;

    @Test
    void resolvesPropertiesManagedVersionsAndLocalParent() throws IOException {
        write("pom.xml", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <groupId>com.example</groupId>
                  <artifactId>parent</artifactId>
                  <version>2.0.0</version>
                  <properties>
                    <jackson.version>2.9.8</jackson.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>org.yaml</groupId>
                        <artifactId>snakeyaml</artifactId>
                        <version>1.33</version>
                      </dependency>
                      <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-dependencies</artifactId>
                        <version>3.2.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>org.slf4j</groupId>
                      <artifactId>slf4j-api</artifactId>
                      <version>2.0.9</version>
                    </dependency>
                  </dependencies>
                </project>
                """);
        File child = write("app/pom.xml", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>2.0.0</version>
                  </parent>
                  <artifactId>app</artifactId>
                  <properties>
                    <h2.version>1.4.200</h2.version>
                  </properties>
                  <dependencies>
                    <dependency>
                      <groupId>com.fasterxml.jackson.core</groupId>
                      <artifactId>jackson-databind</artifactId>
                      <version>${jackson.version}</version>
                    </dependency>
                    <dependency>
                      <groupId>org.yaml</groupId>
                      <artifactId>snakeyaml</artifactId>
                    </dependency>
                    <dependency>
                      <groupId>${project.groupId}</groupId>
                      <artifactId>core</artifactId>
                      <version>${project.version}</version>
                    </dependency>
                    <dependency>
                      <groupId>com.h2database</groupId>
                      <artifactId>h2</artifactId>
                      <version>${h2.version}</version>
                      <scope>test</scope>
                    </dependency>
                    <dependency>
                      <groupId>org.springframework.boot</groupId>
                      <artifactId>spring-boot-starter-web</artifactId>
                    </dependency>
                  </dependencies>
                  <build>
                    <plugins>
                      <plugin>
                        <groupId>org.example</groupId>
                        <artifactId>some-plugin</artifactId>
                        <dependencies>
                          <dependency>
                            <groupId>org.example</groupId>
                            <artifactId>plugin-only</artifactId>
                            <version>1.0</version>
                          </dependency>
                        </dependencies>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);

        Map<String, Dependency> deps = PomParser.parsePom(child).stream()
                .collect(Collectors.toMap(Dependency::packageName, Function.identity()));

        assertEquals("2.0.9", deps.get("org.slf4j:slf4j-api").version(), "inherited from parent");
        assertEquals("2.9.8", deps.get("com.fasterxml.jackson.core:jackson-databind").version());
        assertEquals("1.33", deps.get("org.yaml:snakeyaml").version(), "from dependencyManagement");
        assertEquals("2.0.0", deps.get("com.example:core").version(), "project.* properties");
        assertEquals("1.4.200", deps.get("com.h2database:h2").version());
        assertEquals("test", deps.get("com.h2database:h2").scope());
        assertEquals("compile", deps.get("org.yaml:snakeyaml").scope());
        assertFalse(deps.get("org.springframework.boot:spring-boot-starter-web").hasResolvedVersion(),
                "version from an imported BOM can't be resolved offline");
        assertFalse(deps.containsKey("org.example:plugin-only"), "plugin dependencies are not scanned");
        assertFalse(deps.containsKey("org.springframework.boot:spring-boot-dependencies"));
        assertEquals(6, deps.size());
    }

    @Test
    void leavesUnknownPropertiesUnresolved() throws IOException {
        File pom = write("pom.xml", """
                <project>
                  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
                  <dependencies>
                    <dependency>
                      <groupId>org.example</groupId>
                      <artifactId>lib</artifactId>
                      <version>${undefined.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """);

        List<Dependency> deps = PomParser.parsePom(pom);

        assertEquals(1, deps.size());
        assertFalse(deps.get(0).hasResolvedVersion());
    }

    @Test
    void rejectsDoctypeToPreventXxe() throws IOException {
        File pom = write("pom.xml", """
                <?xml version="1.0"?>
                <!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <project><groupId>&xxe;</groupId></project>
                """);

        IOException e = assertThrows(IOException.class, () -> PomParser.parsePom(pom));
        assertTrue(e.getMessage().contains("DOCTYPE"), e.getMessage());
    }

    private File write(String relative, String content) throws IOException {
        Path path = dir.resolve(relative);
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
        return path.toFile();
    }
}
