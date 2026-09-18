package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import java.util.Objects;

/** Tree-sitter-independent project type declaration exposed to semantic context resolution. */
public record ProjectTypeDeclaration(
        String qualifiedName, JavaFileInfo file, ClassInfo type) {
    public ProjectTypeDeclaration {
        if (qualifiedName == null || qualifiedName.isBlank()) {
            throw new IllegalArgumentException("qualifiedName must not be blank");
        }
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(type, "type");
    }
}
