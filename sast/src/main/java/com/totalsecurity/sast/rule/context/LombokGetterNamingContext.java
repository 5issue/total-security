package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.JavaFileInfo;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/** Normalized project-boundary proof that default Lombok getter naming is safe per source file. */
public final class LombokGetterNamingContext {
    private static final LombokGetterNamingContext UNKNOWN =
            new LombokGetterNamingContext(Set.of());

    private final Set<Path> defaultSafeSources;

    private LombokGetterNamingContext(Set<Path> defaultSafeSources) {
        this.defaultSafeSources = Set.copyOf(defaultSafeSources);
    }

    public static LombokGetterNamingContext unknown() {
        return UNKNOWN;
    }

    public static LombokGetterNamingContext defaultSafeSources(Collection<Path> sourceFiles) {
        Objects.requireNonNull(sourceFiles, "sourceFiles");
        LinkedHashSet<Path> normalized = new LinkedHashSet<>();
        sourceFiles.forEach(path -> normalized.add(normalize(path)));
        return normalized.isEmpty() ? UNKNOWN : new LombokGetterNamingContext(normalized);
    }

    public boolean defaultNamingSafe(JavaFileInfo file) {
        Objects.requireNonNull(file, "file");
        return defaultSafeSources.contains(normalize(file.location().file()));
    }

    public boolean defaultNamingSafe(Path sourceFile) {
        return defaultSafeSources.contains(normalize(sourceFile));
    }

    private static Path normalize(Path path) {
        return Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
    }
}
