package com.totalsecurity.sast.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.treesitter.TSNode;

class JavaSourceParserTest {
    private static final Set<String> EXPECTED_NODE_TYPES = Set.of(
            "class_declaration",
            "method_declaration",
            "marker_annotation",
            "formal_parameter",
            "local_variable_declaration",
            "assignment_expression",
            "method_invocation",
            "return_statement");

    @Test
    void parsesJavaFixtureAndFindsRepresentativeNodes() throws Exception {
        Path fixture = fixturePath("fixtures/SampleController.java");

        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixture)) {
            TSNode root = parsedFile.rootNode();

            assertNotNull(root);
            assertFalse(root.isNull());
            assertEquals("program", root.getType());
            assertFalse(parsedFile.hasSyntaxErrors());

            Set<String> foundNodeTypes = new HashSet<>();
            collectNodeTypes(root, foundNodeTypes);
            assertTrue(
                    foundNodeTypes.containsAll(EXPECTED_NODE_TYPES),
                    () -> "Missing node types: " + difference(EXPECTED_NODE_TYPES, foundNodeTypes));
        }
    }

    @Test
    void reportsSyntaxErrors(@TempDir Path temporaryDirectory) throws Exception {
        Path malformedJava = temporaryDirectory.resolve("Malformed.java");
        Files.writeString(malformedJava, "class Malformed { void broken( { return; } }");

        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(malformedJava)) {
            assertTrue(parsedFile.hasSyntaxErrors());
        }
    }

    private static Path fixturePath(String resourceName) throws URISyntaxException {
        var resource = JavaSourceParserTest.class.getClassLoader().getResource(resourceName);
        assertNotNull(resource, "Fixture not found: " + resourceName);
        return Path.of(resource.toURI());
    }

    private static void collectNodeTypes(TSNode node, Set<String> nodeTypes) {
        nodeTypes.add(node.getType());
        for (int index = 0; index < node.getChildCount(); index++) {
            collectNodeTypes(node.getChild(index), nodeTypes);
        }
    }

    private static Set<String> difference(Set<String> expected, Set<String> actual) {
        Set<String> missing = new HashSet<>(expected);
        missing.removeAll(actual);
        return missing;
    }
}

