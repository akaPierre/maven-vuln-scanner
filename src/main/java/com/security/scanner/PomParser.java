package com.security.scanner;

import com.security.model.Dependency;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the direct dependencies declared in a pom.xml without running Maven.
 *
 * <p>Resolves {@code ${...}} properties, versions from {@code <dependencyManagement>},
 * and anything inherited from a parent pom that exists locally (via {@code <relativePath>}).
 * Versions that only come from a remote parent or an imported BOM can't be resolved this way
 * and are returned with their raw value; use {@link MavenResolver} for full resolution.
 */
public final class PomParser {

    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^}]+)}");
    private static final int MAX_PARENT_DEPTH = 10;

    private PomParser() {
    }

    public static List<Dependency> parsePom(File pomFile) throws IOException {
        Model model = load(pomFile.getAbsoluteFile(), 0);

        Map<String, String> managedVersions = new HashMap<>();
        model.managedVersions.forEach((key, version) ->
                managedVersions.put(interpolate(key, model.properties), version));

        List<Dependency> result = new ArrayList<>();
        for (RawDependency raw : model.dependencies.values()) {
            String groupId = interpolate(raw.groupId, model.properties);
            String artifactId = interpolate(raw.artifactId, model.properties);
            String version = raw.version;
            if (isBlank(version)) {
                version = managedVersions.get(groupId + ":" + artifactId);
            }
            version = interpolate(version, model.properties);
            String scope = isBlank(raw.scope) ? "compile" : raw.scope;
            result.add(new Dependency(groupId, artifactId, version, scope));
        }
        return result;
    }

    /** Effective (merged with parents) view of a pom. */
    private static final class Model {
        final Map<String, String> properties = new HashMap<>();
        final Map<String, String> managedVersions = new HashMap<>();
        final Map<String, RawDependency> dependencies = new LinkedHashMap<>();
    }

    private record RawDependency(String groupId, String artifactId, String version, String scope) {
    }

    private static Model load(File pomFile, int depth) throws IOException {
        Element project = parseXml(pomFile).getDocumentElement();
        Model model = new Model();

        Element parent = child(project, "parent");
        if (parent != null && depth < MAX_PARENT_DEPTH) {
            File parentPom = locateParentPom(pomFile, parent);
            if (parentPom != null) {
                Model parentModel = load(parentPom, depth + 1);
                model.properties.putAll(parentModel.properties);
                model.managedVersions.putAll(parentModel.managedVersions);
                model.dependencies.putAll(parentModel.dependencies);
            }
        }

        String parentGroupId = text(parent, "groupId");
        String parentVersion = text(parent, "version");
        String groupId = firstNonBlank(text(project, "groupId"), parentGroupId);
        String version = firstNonBlank(text(project, "version"), parentVersion);
        String artifactId = text(project, "artifactId");

        putIfNotBlank(model.properties, "project.groupId", groupId);
        putIfNotBlank(model.properties, "project.artifactId", artifactId);
        putIfNotBlank(model.properties, "project.version", version);
        putIfNotBlank(model.properties, "project.parent.groupId", parentGroupId);
        putIfNotBlank(model.properties, "project.parent.version", parentVersion);
        // Deprecated aliases that still appear in older poms
        putIfNotBlank(model.properties, "pom.groupId", groupId);
        putIfNotBlank(model.properties, "pom.version", version);
        putIfNotBlank(model.properties, "version", version);

        Element properties = child(project, "properties");
        if (properties != null) {
            for (Element prop : childElements(properties)) {
                model.properties.put(localName(prop), prop.getTextContent().trim());
            }
        }

        Element depMgmt = child(child(project, "dependencyManagement"), "dependencies");
        for (Element dep : children(depMgmt, "dependency")) {
            // Imported BOMs are not dependencies themselves, and resolving them requires Maven
            if ("import".equals(text(dep, "scope"))) {
                continue;
            }
            String managedVersion = text(dep, "version");
            if (!isBlank(managedVersion)) {
                model.managedVersions.put(text(dep, "groupId") + ":" + text(dep, "artifactId"), managedVersion);
            }
        }

        for (Element dep : children(child(project, "dependencies"), "dependency")) {
            RawDependency raw = new RawDependency(
                    text(dep, "groupId"), text(dep, "artifactId"), text(dep, "version"), text(dep, "scope"));
            if (!isBlank(raw.groupId) && !isBlank(raw.artifactId)) {
                model.dependencies.put(raw.groupId + ":" + raw.artifactId, raw);
            }
        }
        return model;
    }

    /** Returns the parent pom file if it exists locally and matches the declared coordinates. */
    private static File locateParentPom(File pomFile, Element parent) throws IOException {
        Element relativePathEl = child(parent, "relativePath");
        String relativePath = relativePathEl == null ? "../pom.xml" : relativePathEl.getTextContent().trim();
        if (relativePath.isEmpty()) {
            return null;
        }

        File candidate = new File(pomFile.getParentFile(), relativePath);
        if (candidate.isDirectory()) {
            candidate = new File(candidate, "pom.xml");
        }
        if (!candidate.isFile()) {
            return null;
        }

        Element candidateProject = parseXml(candidate).getDocumentElement();
        String candidateGroupId = firstNonBlank(
                text(candidateProject, "groupId"), text(child(candidateProject, "parent"), "groupId"));
        boolean matches = text(parent, "artifactId").equals(text(candidateProject, "artifactId"))
                && text(parent, "groupId").equals(candidateGroupId);
        return matches ? candidate.getCanonicalFile() : null;
    }

    static String interpolate(String value, Map<String, String> properties) {
        if (value == null) {
            return null;
        }
        String current = value.trim();
        // Properties may reference other properties; bound the passes to avoid cycles
        for (int pass = 0; pass < 10 && current.contains("${"); pass++) {
            Matcher m = PROPERTY.matcher(current);
            StringBuilder sb = new StringBuilder();
            boolean replaced = false;
            while (m.find()) {
                String replacement = properties.get(m.group(1));
                if (replacement != null) {
                    replaced = true;
                }
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement != null ? replacement : m.group()));
            }
            m.appendTail(sb);
            current = sb.toString();
            if (!replaced) {
                break;
            }
        }
        return current;
    }

    private static Document parseXml(File file) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Hardening against XXE: a scanner will be pointed at untrusted poms
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setNamespaceAware(true);

            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(null);
            return builder.parse(file);
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid pom " + file + ": " + e.getMessage(), e);
        }
    }

    private static Element child(Element parent, String name) {
        if (parent == null) {
            return null;
        }
        for (Element el : childElements(parent)) {
            if (name.equals(localName(el))) {
                return el;
            }
        }
        return null;
    }

    private static List<Element> children(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        if (parent != null) {
            for (Element el : childElements(parent)) {
                if (name.equals(localName(el))) {
                    result.add(el);
                }
            }
        }
        return result;
    }

    private static List<Element> childElements(Element parent) {
        List<Element> result = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                result.add((Element) node);
            }
        }
        return result;
    }

    private static String localName(Element el) {
        return el.getLocalName() != null ? el.getLocalName() : el.getNodeName();
    }

    private static String text(Element parent, String name) {
        Element el = child(parent, name);
        return el == null ? "" : el.getTextContent().trim();
    }

    private static String firstNonBlank(String a, String b) {
        return isBlank(a) ? b : a;
    }

    private static void putIfNotBlank(Map<String, String> map, String key, String value) {
        if (!isBlank(value)) {
            map.put(key, value);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
