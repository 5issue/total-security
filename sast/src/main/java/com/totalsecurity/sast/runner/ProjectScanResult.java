package com.totalsecurity.sast.runner;

import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.interprocedural.UnsupportedInterproceduralFlow;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

public record ProjectScanResult(
        Path projectRoot,
        ProjectScanStatus status,
        List<Path> discoveredJavaFiles,
        List<Path> successfullyParsedFiles,
        List<Path> successfullyExtractedFiles,
        List<ProjectScanDiagnostic> diagnostics,
        List<FindingResult> findings,
        List<UnsupportedInterproceduralFlow> unsupportedInterprocedural,
        ProjectScanSummary summary) {
    public ProjectScanResult {
        projectRoot = Objects.requireNonNull(projectRoot, "projectRoot").toAbsolutePath().normalize();
        Objects.requireNonNull(status, "status");
        discoveredJavaFiles = List.copyOf(discoveredJavaFiles);
        successfullyParsedFiles = List.copyOf(successfullyParsedFiles);
        successfullyExtractedFiles = List.copyOf(successfullyExtractedFiles);
        diagnostics = List.copyOf(diagnostics);
        findings = List.copyOf(findings);
        unsupportedInterprocedural = List.copyOf(unsupportedInterprocedural);
        Objects.requireNonNull(summary, "summary");
        if (summary.discoveredJavaFiles() != discoveredJavaFiles.size()
                || summary.successfullyParsedFiles() != successfullyParsedFiles.size()
                || summary.successfullyExtractedFiles() != successfullyExtractedFiles.size()
                || summary.diagnostics() != diagnostics.size()
                || summary.findings() != findings.size()
                || summary.unsupportedInterproceduralFlows()
                        != unsupportedInterprocedural.size()) {
            throw new IllegalArgumentException("Summary counts must match scan collections");
        }
    }

    public Path relativePath(Path path) {
        Path normalized = path.isAbsolute()
                ? path.toAbsolutePath().normalize()
                : projectRoot.resolve(path).normalize();
        return normalized.startsWith(projectRoot) ? projectRoot.relativize(normalized) : path;
    }
}
