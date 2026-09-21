package com.totalsecurity.sast.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SastParserApplicationTest {
    @Test
    void rendersChecklistFindingWithoutBlankOrInventedCwe(@TempDir Path project)
            throws Exception {
        Path source = project.resolve("src/main/java/example/JwtConfig.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package example;
                class JwtConfig {
                    String jwtSecret = "cli-redaction-signing-material";
                }
                """, StandardCharsets.UTF_8);
        ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errorBytes = new ByteArrayOutputStream();

        int exitCode;
        try (PrintStream output = new PrintStream(outputBytes, true, StandardCharsets.UTF_8);
                PrintStream error = new PrintStream(errorBytes, true, StandardCharsets.UTF_8)) {
            exitCode = SastParserApplication.run(
                    new String[] {"scan", project.toString()}, output, error);
        }

        String output = outputBytes.toString(StandardCharsets.UTF_8);
        assertEquals(0, exitCode);
        assertTrue(output.lines().anyMatch(line -> line.equals(
                "[HIGH] AUTHN_06_HARDCODED_SIGNING_MATERIAL")));
        assertFalse(output.contains("CWE-"));
        assertFalse(output.contains("cli-redaction-signing-material"));
        assertTrue(errorBytes.toString(StandardCharsets.UTF_8).isEmpty());
    }
}
