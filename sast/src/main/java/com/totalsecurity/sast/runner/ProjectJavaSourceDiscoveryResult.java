package com.totalsecurity.sast.runner;

import java.nio.file.Path;
import java.util.List;

public record ProjectJavaSourceDiscoveryResult(
        Path projectRoot,
        List<Path> sourceRoots,
        List<Path> javaFiles,
        List<ProjectScanDiagnostic> diagnostics) {
    public ProjectJavaSourceDiscoveryResult {
        sourceRoots = List.copyOf(sourceRoots);
        javaFiles = List.copyOf(javaFiles);
        diagnostics = List.copyOf(diagnostics);
    }
}
