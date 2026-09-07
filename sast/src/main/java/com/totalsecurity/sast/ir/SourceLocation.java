package com.totalsecurity.sast.ir;

import java.nio.file.Path;
import java.util.Objects;

/** A 1-based source range. Columns retain Tree-sitter's UTF-8 byte-column semantics. */
public record SourceLocation(
        Path file, int startLine, int startColumn, int endLine, int endColumn) {
    public SourceLocation {
        Objects.requireNonNull(file, "file");
        if (startLine < 1 || startColumn < 1 || endLine < 1 || endColumn < 1) {
            throw new IllegalArgumentException("Source locations are 1-based");
        }
    }
}

