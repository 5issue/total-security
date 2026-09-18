package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import com.totalsecurity.sast.rule.context.ProjectTypeDeclaration;
import com.totalsecurity.sast.rule.context.ProjectTypeLookup;
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
public final class ProjectClassIndex implements ProjectTypeLookup {
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

    public boolean contains(String qualifiedName) {
        return !candidates(qualifiedName).isEmpty();
    }

    @Override
    public List<ProjectTypeDeclaration> declarations(String qualifiedName) {
        return candidates(qualifiedName).stream()
                .map(entry -> new ProjectTypeDeclaration(
                        entry.qualifiedName(), entry.file(), entry.type()))
                .toList();
    }

    /** Exact, project-local declared subtype traversal. Duplicate or unresolved types stop proof. */
    public boolean isDeclaredSubtypeOf(String subtype, String supertype) {
        Objects.requireNonNull(subtype, "subtype");
        Objects.requireNonNull(supertype, "supertype");
        if (isAmbiguousProjectType(subtype) || isAmbiguousProjectType(supertype)) {
            return false;
        }
        return isDeclaredSubtypeOf(subtype, supertype, new LinkedHashSet<>());
    }

    /**
     * Proves a relationship from one exact source declaration. Duplicate intermediate
     * declarations still stop the proof.
     */
    boolean isDeclaredSubtypeOf(ProjectClassEntry subtype, String supertype) {
        Objects.requireNonNull(subtype, "subtype");
        Objects.requireNonNull(supertype, "supertype");
        if (isAmbiguousProjectType(supertype)) {
            return false;
        }
        return isDeclaredSubtypeOf(subtype, supertype, new LinkedHashSet<>());
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

    /** All source declarations, including duplicate FQNs, in discovery order. */
    public List<ProjectClassEntry> entries() {
        return byQualifiedName.values().stream().flatMap(List::stream).toList();
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

    private boolean isDeclaredSubtypeOf(
            String subtype, String supertype, Set<String> visited) {
        if (isAmbiguousProjectType(subtype)) {
            return false;
        }
        if (subtype.equals(supertype)) {
            return true;
        }
        if (!visited.add(subtype)) {
            return false;
        }
        Optional<ProjectClassEntry> entry = uniqueClass(subtype);
        if (entry.isEmpty()) {
            return false;
        }
        ProjectClassEntry current = entry.orElseThrow();
        LightweightTypeContext types = new LightweightTypeContext(current.file(), this::contains);
        return java.util.stream.Stream.concat(
                        current.type().extendsTypes().stream(),
                        current.type().implementsTypes().stream())
                .map(types::qualifyTypeShape)
                .flatMap(Optional::stream)
                .anyMatch(parent -> parent.equals(supertype)
                        || isDeclaredSubtypeOf(parent, supertype, visited));
    }

    private boolean isDeclaredSubtypeOf(
            ProjectClassEntry subtype, String supertype, Set<String> visited) {
        if (subtype.qualifiedName().equals(supertype)) {
            return true;
        }
        if (!visited.add(subtype.qualifiedName())) {
            return false;
        }
        LightweightTypeContext types = new LightweightTypeContext(subtype.file(), this::contains);
        return java.util.stream.Stream.concat(
                        subtype.type().extendsTypes().stream(),
                        subtype.type().implementsTypes().stream())
                .map(types::qualifyTypeShape)
                .flatMap(Optional::stream)
                .anyMatch(parent -> parent.equals(supertype)
                        || uniqueClass(parent)
                                .map(entry -> isDeclaredSubtypeOf(entry, supertype, visited))
                                .orElse(false));
    }

    private boolean isAmbiguousProjectType(String qualifiedName) {
        return candidates(qualifiedName).size() > 1;
    }

    private static Map<String, List<ProjectClassEntry>> immutableLists(
            Map<String, List<ProjectClassEntry>> source) {
        LinkedHashMap<String, List<ProjectClassEntry>> result = new LinkedHashMap<>();
        source.forEach((key, value) -> result.put(key, List.copyOf(value)));
        return Collections.unmodifiableMap(result);
    }
}
