package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.ParameterInfo;
import java.util.Objects;

public record ParameterContext(
        JavaFileInfo file,
        ClassInfo enclosingClass,
        MethodInfo enclosingMethod,
        ParameterInfo parameter,
        LightweightTypeContext types) {
    public ParameterContext {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(enclosingClass, "enclosingClass");
        Objects.requireNonNull(enclosingMethod, "enclosingMethod");
        Objects.requireNonNull(parameter, "parameter");
        Objects.requireNonNull(types, "types");
    }
}
