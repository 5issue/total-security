package com.totalsecurity.sast.runner;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Immutable input for one local project scan. Explicit source roots are project-root relative or contained absolute paths. */
public record ProjectScanRequest(
        Path projectRoot,
        List<Path> sourceRoots,
        boolean includeTests,
        Charset charset) {
    public ProjectScanRequest {
        Objects.requireNonNull(projectRoot, "projectRoot");
        sourceRoots = List.copyOf(sourceRoots);
        Objects.requireNonNull(charset, "charset");
    }

    public static ProjectScanRequest productionJava(Path projectRoot) {
        return new ProjectScanRequest(projectRoot, List.of(), false, StandardCharsets.UTF_8);
    }
}
