package com.totalsecurity.sast.cli;

import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.parser.SyntaxTreePrinter;
import com.totalsecurity.sast.runner.ProjectScanResult;
import com.totalsecurity.sast.runner.ProjectScanStatus;
import com.totalsecurity.sast.runner.ProjectScanner;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Command-line entry point for syntax-tree inspection and local project scanning. */
public final class SastParserApplication {
    private SastParserApplication() {}

    public static void main(String[] args) {
        int exitCode = run(args, System.out, System.err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args, PrintStream out, PrintStream error) {
        if (args.length == 2 && args[0].equals("scan")) {
            return scan(Path.of(args[1]), out, error);
        }
        if (args.length == 1) {
            return printSyntaxTree(Path.of(args[0]), out, error);
        }
        error.println("Usage: sast-parser <path-to-java-file>");
        error.println("   or: sast-parser scan <project-root>");
        return 2;
    }

    private static int printSyntaxTree(Path file, PrintStream out, PrintStream error) {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(file)) {
            out.println("file: " + parsedFile.path());
            out.println("hasSyntaxErrors: " + parsedFile.hasSyntaxErrors());
            new SyntaxTreePrinter().print(parsedFile, out);
            return 0;
        } catch (Exception exception) {
            error.println("Parse failed: " + exception.getMessage());
            return 1;
        }
    }

    private static int scan(Path projectRoot, PrintStream out, PrintStream error) {
        ProjectScanResult result = ProjectScanner.javaDefaults().scan(projectRoot);
        out.println("Project: " + result.projectRoot());
        out.println("Java files discovered: " + result.summary().discoveredJavaFiles());
        out.println("Parsed: " + result.summary().successfullyParsedFiles());
        out.println("Extracted: " + result.summary().successfullyExtractedFiles());
        out.println("Diagnostics: " + result.summary().diagnostics());
        out.println("Findings: " + result.summary().findings());
        out.println("Unsupported interprocedural: "
                + result.summary().unsupportedInterproceduralFlows());
        result.unsupportedInterprocedural().stream()
                .collect(Collectors.groupingBy(
                        item -> item.reason().name(), TreeMap::new, Collectors.counting()))
                .forEach((reason, count) -> out.println("  " + reason + ": " + count));
        for (var finding : result.findings()) {
            out.println();
            out.println("[" + finding.severity() + "] " + finding.ruleId()
                    + " " + finding.cwe());
            out.println(result.relativePath(finding.primaryLocation().file())
                    + ":" + finding.primaryLocation().startLine());
        }
        if (result.status() == ProjectScanStatus.FAILED) {
            result.diagnostics().stream().filter(item -> item.fatal()).forEach(item ->
                    error.println(item.stage() + ": " + item.message()));
            return 1;
        }
        return 0;
    }
}
