package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record JavaFileInfo(
        Optional<String> packageName,
        List<String> imports,
        List<ClassInfo> types,
        SourceLocation location) {
    public JavaFileInfo {
        packageName = Objects.requireNonNull(packageName, "packageName");
        imports = List.copyOf(imports);
        types = List.copyOf(types);
        Objects.requireNonNull(location, "location");
    }
}

