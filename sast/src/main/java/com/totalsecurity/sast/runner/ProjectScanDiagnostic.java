package com.totalsecurity.sast.runner;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/** Stable user-facing project diagnostic without an exposed stack trace. */
public record ProjectScanDiagnostic(
        Optional<Path> path,
        ProjectScanStage stage,
        String message,
        boolean fatal) {
    public ProjectScanDiagnostic {
        path = Objects.requireNonNull(path, "path");
        Objects.requireNonNull(stage, "stage");
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("message must not be blank");
        }
    }
}
