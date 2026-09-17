package com.totalsecurity.sast.runner;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.detector.redirect.OpenRedirectDetector;
import com.totalsecurity.sast.detector.sql.SqlInjectionDetector;
import com.totalsecurity.sast.detector.xss.XssDetector;
import com.totalsecurity.sast.interprocedural.UnsupportedInterproceduralReason;
import com.totalsecurity.sast.pattern.credential.HardcodedCredentialDetector;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProjectScannerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void scansAnArbitraryExternalProjectRoot() throws Exception {
        Path project = project("external-project");
        java(project, "src/main/java/example/App.java", "package example; class App {} ");

        ProjectScanResult result = scan(project);

        assertEquals(project.toAbsolutePath().normalize(), result.projectRoot());
        assertEquals(List.of(Path.of("src/main/java/example/App.java")),
                result.discoveredJavaFiles());
    }

    @Test
    void discoversConventionalProductionSourceRoot() throws Exception {
        Path project = project("production-root");
        java(project, "src/main/java/example/Main.java", "package example; class Main {} ");

        ProjectScanResult result = scan(project);

        assertEquals(1, result.summary().discoveredJavaFiles());
    }

    @Test
    void excludesTestSourcesByDefault() throws Exception {
        Path project = project("exclude-tests");
        java(project, "src/main/java/example/Main.java", "package example; class Main {} ");
        java(project, "src/test/java/example/MainTest.java", "package example; class MainTest {} ");

        ProjectScanResult result = scan(project);

        assertEquals(List.of(Path.of("src/main/java/example/Main.java")),
                result.discoveredJavaFiles());
    }

    @Test
    void includesTestSourcesOnlyWhenRequested() throws Exception {
        Path project = project("include-tests");
        java(project, "src/main/java/example/Main.java", "package example; class Main {} ");
        java(project, "src/test/java/example/MainTest.java", "package example; class MainTest {} ");

        ProjectScanResult result = ProjectScanner.javaDefaults().scan(new ProjectScanRequest(
                project, List.of(), true, StandardCharsets.UTF_8));

        assertEquals(2, result.summary().discoveredJavaFiles());
    }

    @Test
    void discoversMultipleModuleProductionRoots() throws Exception {
        Path project = project("multi-module");
        java(project, "module-b/src/main/java/b/B.java", "package b; class B {} ");
        java(project, "module-a/src/main/java/a/A.java", "package a; class A {} ");

        ProjectScanResult result = scan(project);

        assertEquals(List.of(
                Path.of("module-a/src/main/java/a/A.java"),
                Path.of("module-b/src/main/java/b/B.java")), result.discoveredJavaFiles());
    }

    @Test
    void excludesBuildMetadataAndGeneratedDirectories() throws Exception {
        Path project = project("excluded-directories");
        java(project, "src/main/java/example/App.java", "package example; class App {} ");
        for (String directory : List.of(
                ".git", ".gradle", "build", "target", "out", "node_modules", ".idea",
                "generated", ".gradle-user-home")) {
            java(project, directory + "/src/main/java/ignored/Ignored.java",
                    "package ignored; class Ignored {} ");
        }

        ProjectScanResult result = scan(project);

        assertEquals(List.of(Path.of("src/main/java/example/App.java")),
                result.discoveredJavaFiles());
    }

    @Test
    void discoveryOrderIsDeterministic() throws Exception {
        Path project = project("ordered-discovery");
        java(project, "z/src/main/java/z/Z.java", "package z; class Z {} ");
        java(project, "a/src/main/java/a/A.java", "package a; class A {} ");

        List<Path> first = scan(project).discoveredJavaFiles();
        List<Path> second = scan(project).discoveredJavaFiles();

        assertEquals(first, second);
        assertEquals(Path.of("a/src/main/java/a/A.java"), first.getFirst());
    }

    @Test
    void validFileIsParsedAndExtractedOnce() throws Exception {
        Path project = project("valid-file");
        java(project, "src/main/java/example/App.java",
                "package example; class App { String value() { return \"ok\"; } }");

        ProjectScanResult result = scan(project);

        assertEquals(1, result.summary().successfullyParsedFiles());
        assertEquals(1, result.summary().successfullyExtractedFiles());
    }

    @Test
    void malformedFileDoesNotStopOtherFiles() throws Exception {
        Path project = project("malformed-continue");
        java(project, "src/main/java/example/Good.java", "package example; class Good {} ");
        java(project, "src/main/java/example/Broken.java", "package example; class Broken { void x( { ");

        ProjectScanResult result = scan(project);

        assertEquals(2, result.summary().discoveredJavaFiles());
        assertEquals(1, result.summary().successfullyParsedFiles());
        assertEquals(1, result.summary().successfullyExtractedFiles());
    }

    @Test
    void malformedFileProducesStructuredParseDiagnostic() throws Exception {
        Path project = project("malformed-diagnostic");
        java(project, "src/main/java/example/Broken.java", "class Broken { void x( { ");

        ProjectScanResult result = scan(project);

        assertTrue(result.diagnostics().stream().anyMatch(item ->
                item.stage() == ProjectScanStage.PARSE
                        && item.path().orElseThrow().equals(
                                Path.of("src/main/java/example/Broken.java"))));
        assertEquals(ProjectScanStatus.PARTIAL, result.status());
    }

    @Test
    void detectsCrossClassSqlFlowThroughRunner() throws Exception {
        Path project = crossClassSqlProject("cross-sql");

        ProjectScanResult result = scan(project);

        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(SqlInjectionDetector.RULE_ID)));
    }

    @Test
    void preservesSameClassInterproceduralFinding() throws Exception {
        Path project = project("same-class-sql");
        java(project, "src/main/java/example/App.java", """
                package example;
                import java.sql.Statement;
                import org.springframework.web.bind.annotation.RequestParam;
                class App {
                    Statement statement;
                    void entry(@RequestParam String input) throws Exception { helper(input); }
                    void helper(String value) throws Exception { statement.executeQuery(value); }
                }
                """);

        ProjectScanResult result = scan(project);

        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(SqlInjectionDetector.RULE_ID)));
    }

    @Test
    void includesHardcodedCredentialPatternFinding() throws Exception {
        Path project = project("hardcoded-pattern");
        java(project, "src/main/java/example/Secrets.java", """
                package example;
                class Secrets { String password = "do-not-print-this"; }
                """);

        ProjectScanResult result = scan(project);

        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(HardcodedCredentialDetector.RULE_ID)));
        assertTrue(result.findings().stream()
                .noneMatch(finding -> finding.evidence().contains("do-not-print-this")));
    }

    @Test
    void includesExistingContextSensitiveDetector() throws Exception {
        Path project = project("open-redirect");
        java(project, "src/main/java/example/RedirectController.java", """
                package example;
                import jakarta.servlet.http.HttpServletResponse;
                import org.springframework.web.bind.annotation.RequestParam;
                class RedirectController {
                    void redirect(@RequestParam String target, HttpServletResponse response)
                            throws Exception {
                        response.sendRedirect(target);
                    }
                }
                """);

        ProjectScanResult result = scan(project);

        assertEquals(1, result.findings().stream().filter(finding ->
                finding.ruleId().equals(OpenRedirectDetector.RULE_ID)).count());
    }

    @Test
    void duplicateFqnRetainsLocalContextAndPatternAnalysisWithoutCrossLinking() throws Exception {
        Path project = project("duplicate-fqn-local-analysis");
        java(project, "module-a/src/main/java/duplicate/DuplicateController.java", """
                package duplicate;
                import jakarta.servlet.http.HttpServletResponse;
                import org.springframework.web.bind.annotation.RequestParam;
                class DuplicateController {
                    void redirect(@RequestParam String target, HttpServletResponse response)
                            throws Exception {
                        response.sendRedirect(target);
                    }
                    void entry(@RequestParam String input) throws Exception { helper(input); }
                }
                """);
        java(project, "module-b/src/main/java/duplicate/DuplicateController.java", """
                package duplicate;
                import jakarta.servlet.http.HttpServletResponse;
                import java.sql.Statement;
                import org.springframework.web.bind.annotation.RequestParam;
                class DuplicateController {
                    Statement statement;
                    String password = "duplicate-secret";
                    void helper(String sql) throws Exception { statement.executeQuery(sql); }
                    void render(@RequestParam String input, HttpServletResponse response)
                            throws Exception {
                        response.setContentType("text/html");
                        response.getWriter().write(input);
                    }
                }
                """);

        ProjectScanResult result = scan(project);

        assertTrue(result.unsupportedInterprocedural().stream().anyMatch(item ->
                item.reason() == UnsupportedInterproceduralReason.AMBIGUOUS_CLASS
                        && item.detail().contains("duplicate.DuplicateController")));
        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(OpenRedirectDetector.RULE_ID)));
        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(XssDetector.RULE_ID)));
        assertTrue(result.findings().stream().anyMatch(finding ->
                finding.ruleId().equals(HardcodedCredentialDetector.RULE_ID)));
        assertTrue(result.findings().stream().noneMatch(finding ->
                finding.ruleId().equals(SqlInjectionDetector.RULE_ID)));
    }

    @Test
    void findingsAreSortedByRelativeFileLineAndRule() throws Exception {
        Path project = project("sorted-findings");
        java(project, "src/main/java/z/Z.java",
                "package z; class Z { String password = \"z-secret\"; }");
        java(project, "src/main/java/a/A.java",
                "package a; class A { String password = \"a-secret\"; }");

        ProjectScanResult result = scan(project);

        assertEquals(2, result.findings().size());
        assertEquals(Path.of("src/main/java/a/A.java"),
                result.relativePath(result.findings().getFirst().primaryLocation().file()));
    }

    @Test
    void invalidProjectPathReturnsFatalResult() {
        Path missing = temporaryDirectory.resolve("missing-project");

        ProjectScanResult result = scan(missing);

        assertEquals(ProjectScanStatus.FAILED, result.status());
        assertTrue(result.diagnostics().stream().anyMatch(ProjectScanDiagnostic::fatal));
    }

    @Test
    void emptyProjectReturnsStableEmptyResult() throws Exception {
        Path project = project("empty-project");

        ProjectScanResult result = scan(project);

        assertEquals(0, result.summary().discoveredJavaFiles());
        assertEquals(0, result.summary().findings());
        assertFalse(result.status() == ProjectScanStatus.FAILED);
    }

    @Test
    void explicitSourceRootCannotEscapeProjectRoot() throws Exception {
        Path project = project("contained-project");
        Path outside = project("outside-project");
        java(outside, "src/main/java/outside/Outside.java", "package outside; class Outside {} ");

        ProjectScanResult result = ProjectScanner.javaDefaults().scan(new ProjectScanRequest(
                project,
                List.of(outside.resolve("src/main/java")),
                false,
                StandardCharsets.UTF_8));

        assertEquals(ProjectScanStatus.FAILED, result.status());
        assertTrue(result.discoveredJavaFiles().isEmpty());
    }

    @Test
    void scanningDoesNotModifyTargetSource() throws Exception {
        Path project = project("read-only-target");
        Path source = java(project, "src/main/java/example/App.java",
                "package example; class App { String value = \"unchanged\"; }");
        byte[] before = Files.readAllBytes(source);

        scan(project);

        assertArrayEquals(before, Files.readAllBytes(source));
    }

    private ProjectScanResult scan(Path project) {
        return ProjectScanner.javaDefaults().scan(project);
    }

    private Path project(String name) throws IOException {
        return Files.createDirectories(temporaryDirectory.resolve(name));
    }

    private static Path java(Path project, String relative, String source) throws IOException {
        Path file = project.resolve(relative);
        Files.createDirectories(file.getParent());
        return Files.writeString(file, source, StandardCharsets.UTF_8);
    }

    private Path crossClassSqlProject(String name) throws IOException {
        Path project = project(name);
        java(project, "src/main/java/example/Controller.java", """
                package example;
                import org.springframework.web.bind.annotation.RequestParam;
                class Controller {
                    Service service;
                    void entry(@RequestParam String input) throws Exception { service.run(input); }
                }
                """);
        java(project, "src/main/java/example/Service.java", """
                package example;
                class Service {
                    Repository repository;
                    void run(String value) throws Exception { repository.query(value); }
                }
                """);
        java(project, "src/main/java/example/Repository.java", """
                package example;
                import java.sql.Statement;
                class Repository {
                    Statement statement;
                    void query(String sql) throws Exception { statement.executeQuery(sql); }
                }
                """);
        return project;
    }
}
