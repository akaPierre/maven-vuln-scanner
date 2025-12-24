package com.security.scanner;

import com.security.model.Dependency;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PomParser {
    public static List<Dependency> parsePom(File pomFile) {
        List<Dependency> dependencies = new ArrayList<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(pomFile);

            NodeList depNodes = doc.getElementsByTagName("dependency");
            for (int i = 0; i < depNodes.getLength(); i++) {
                Node dep = depNodes.item(i);
                String groupId = getTextContent(dep, "groupId");
                String artifactId = getTextContent(dep, "artifactId");
                String version = getTextContent(dep, "version");

                if (StringUtils.isNotBlank(groupId) && StringUtils.isNotBlank(artifactId)) {
                    dependencies.add(new Dependency(groupId, artifactId, version));
                }
            }
        } catch (Exception e) {
            System.err.println("Error parsing " + pomFile.getName() + ": " + e.getMessage());
        }
        return dependencies;
    }

    private static String getTextContent(Node parent, String tagName) {
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (tagName.equals(node.getNodeName())) {
                return node.getTextContent();
            }
        }
        return "";
    }
}