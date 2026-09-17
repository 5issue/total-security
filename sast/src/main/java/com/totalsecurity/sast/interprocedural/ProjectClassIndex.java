package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Project-local FQN index. Duplicate FQNs remain ambiguous and are never selected. */
public final class ProjectClassIndex {
    private final Map<String, List<ProjectClassEntry>> byQualifiedName;
    private final Map<String, List<ProjectClassEntry>> bySimpleName;

    public ProjectClassIndex(Collection<JavaFileInfo> files) {
        Objects.requireNonNull(files, "files");
        LinkedHashMap<String, List<ProjectClassEntry>> qualified = new LinkedHashMap<>();
        LinkedHashMap<String, List<ProjectClassEntry>> simple = new LinkedHashMap<>();
        for (JavaFileInfo file : files) {
            Objects.requireNonNull(file, "file");
            for (ClassInfo type : file.types()) {
                String fqn = qualifiedName(file, type);
                ProjectClassEntry entry = new ProjectClassEntry(fqn, file, type);
                qualified.computeIfAbsent(fqn, ignored -> new ArrayList<>()).add(entry);
                simple.computeIfAbsent(type.name(), ignored -> new ArrayList<>()).add(entry);
            }
        }
        this.byQualifiedName = immutableLists(qualified);
        this.bySimpleName = immutableLists(simple);
    }

    public List<ProjectClassEntry> candidates(String qualifiedName) {
        return byQualifiedName.getOrDefault(qualifiedName, List.of());
    }

    public Optional<ProjectClassEntry> uniqueClass(String qualifiedName) {
        List<ProjectClassEntry> candidates = candidates(qualifiedName);
        return candidates.size() == 1 ? Optional.of(candidates.getFirst()) : Optional.empty();
    }

    public List<ProjectClassEntry> classesNamed(String simpleName) {
        return bySimpleName.getOrDefault(simpleName, List.of());
    }

    public List<ProjectClassEntry> uniqueClasses() {
        return byQualifiedName.values().stream()
                .filter(entries -> entries.size() == 1)
                .map(List::getFirst)
                .toList();
    }

    public Set<String> ambiguousQualifiedNames() {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        byQualifiedName.forEach((name, entries) -> {
            if (entries.size() > 1) {
                result.add(name);
            }
        });
        return Collections.unmodifiableSet(result);
    }

    public List<ProjectClassEntry> ambiguousEntries(String qualifiedName) {
        List<ProjectClassEntry> entries = candidates(qualifiedName);
        return entries.size() > 1 ? entries : List.of();
    }

    public static String qualifiedName(JavaFileInfo file, ClassInfo type) {
        return file.packageName().map(name -> name + "." + type.name()).orElse(type.name());
    }

    private static Map<String, List<ProjectClassEntry>> immutableLists(
            Map<String, List<ProjectClassEntry>> source) {
        LinkedHashMap<String, List<ProjectClassEntry>> result = new LinkedHashMap<>();
        source.forEach((key, value) -> result.put(key, List.copyOf(value)));
        return Collections.unmodifiableMap(result);
    }
}
