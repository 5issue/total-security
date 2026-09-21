package com.totalsecurity.sast.runner;

import com.totalsecurity.sast.rule.context.LombokGetterNamingContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Conservative project-boundary check for Lombok settings that can change getter names. */
public final class LombokConfigurationDiscovery {
    private static final Pattern RELEVANT_NAMING_KEY = Pattern.compile(
            "^(?:clear\\s+)?(?:lombok\\.accessors\\.(?:fluent|prefix|capitalization)"
                    + "|lombok\\.getter\\.noIsPrefix)(?:\\s*(?:\\+=|-=|=).*)?$");
    private static final Pattern IMPORT_DIRECTIVE = Pattern.compile("^import\\s+\\S.*$");

    public LombokGetterNamingContext inspect(Collection<Path> sourceFiles) {
        Objects.requireNonNull(sourceFiles, "sourceFiles");
        Set<Path> safe = new LinkedHashSet<>();
        for (Path sourceFile : sourceFiles) {
            Path normalized = Objects.requireNonNull(sourceFile, "sourceFile")
                    .toAbsolutePath().normalize();
            if (defaultNamingIsProvable(normalized)) {
                safe.add(normalized);
            }
        }
        return LombokGetterNamingContext.defaultSafeSources(safe);
    }

    private static boolean defaultNamingIsProvable(Path sourceFile) {
        if (!Files.isRegularFile(sourceFile)) {
            return false;
        }
        for (Path directory = sourceFile.getParent(); directory != null;
                directory = directory.getParent()) {
            Path config = directory.resolve("lombok.config");
            if (Files.notExists(config)) {
                continue;
            }
            if (!Files.isRegularFile(config) || Files.isSymbolicLink(config)) {
                return false;
            }
            try {
                if (containsRelevantNamingKey(Files.readAllLines(config, StandardCharsets.UTF_8))) {
                    return false;
                }
            } catch (IOException | RuntimeException exception) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsRelevantNamingKey(List<String> lines) {
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (index == 0 && line.startsWith("\uFEFF")) {
                line = line.substring(1);
            }
            String normalized = line.strip();
            if (normalized.isEmpty() || normalized.startsWith("#")) {
                continue;
            }
            int comment = normalized.indexOf('#');
            if (comment >= 0) {
                normalized = normalized.substring(0, comment).stripTrailing();
            }
            if (RELEVANT_NAMING_KEY.matcher(normalized).matches()
                    || IMPORT_DIRECTIVE.matcher(normalized).matches()) {
                return true;
            }
        }
        return false;
    }
}
