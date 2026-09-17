package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import java.util.Objects;

/** One extracted project type with its stable fully-qualified owner name. */
public record ProjectClassEntry(String qualifiedName, JavaFileInfo file, ClassInfo type) {
    public ProjectClassEntry {
        if (qualifiedName == null || qualifiedName.isBlank()) {
            throw new IllegalArgumentException("qualifiedName must not be blank");
        }
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(type, "type");
    }
}
