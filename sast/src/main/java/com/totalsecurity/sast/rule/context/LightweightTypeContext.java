package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.TypeKind;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/** Conservative import-aware name qualification without compiler symbol resolution. */
public final class LightweightTypeContext {
    private static final Set<String> IMPLICIT_JAVA_LANG_TYPES = Set.of(
            "Boolean", "Byte", "Character", "Class", "Double", "Enum", "Exception",
            "Float", "Integer", "Iterable", "Long", "Number", "Object", "Runtime",
            "RuntimeException", "Short", "String", "StringBuilder", "StringBuffer",
            "System", "Throwable", "Void");

    private final JavaFileInfo file;
    private final Predicate<String> projectTypeExists;
    private final Predicate<String> nestedProjectTypeExists;
    private final Predicate<String> exactNestedProjectTypeExists;
    private final Optional<ClassInfo> enclosingType;

    public LightweightTypeContext(JavaFileInfo file) {
        this(file, ignored -> false, ignored -> false, ignored -> false, Optional.empty());
    }

    public LightweightTypeContext(JavaFileInfo file, Predicate<String> projectTypeExists) {
        this(file, projectTypeExists, ignored -> false, ignored -> false, Optional.empty());
    }

    public LightweightTypeContext(
            JavaFileInfo file, Predicate<String> projectTypeExists, ClassInfo enclosingType) {
        this(file, projectTypeExists, ignored -> false, ignored -> false,
                Optional.of(Objects.requireNonNull(enclosingType, "enclosingType")));
    }

    public LightweightTypeContext(
            JavaFileInfo file, ProjectTypeLookup projectTypes, ClassInfo enclosingType) {
        this(
                file,
                Objects.requireNonNull(projectTypes, "projectTypes")::contains,
                qualifiedName -> projectTypes.declarations(qualifiedName).stream()
                        .anyMatch(declaration -> !declaration.type()
                                .enclosingTypeNames().isEmpty()),
                qualifiedName -> isExactSupportedNestedType(projectTypes, qualifiedName),
                Optional.of(Objects.requireNonNull(enclosingType, "enclosingType")));
    }

    private LightweightTypeContext(
            JavaFileInfo file,
            Predicate<String> projectTypeExists,
            Predicate<String> nestedProjectTypeExists,
            Predicate<String> exactNestedProjectTypeExists,
            Optional<ClassInfo> enclosingType) {
        this.file = Objects.requireNonNull(file, "file");
        this.projectTypeExists = Objects.requireNonNull(projectTypeExists, "projectTypeExists");
        this.nestedProjectTypeExists = Objects.requireNonNull(
                nestedProjectTypeExists, "nestedProjectTypeExists");
        this.exactNestedProjectTypeExists = Objects.requireNonNull(
                exactNestedProjectTypeExists, "exactNestedProjectTypeExists");
        this.enclosingType = Objects.requireNonNull(enclosingType, "enclosingType");
    }

    public JavaFileInfo file() {
        return file;
    }

    public Optional<String> qualifyType(String declaredType) {
        String type = baseType(declaredType);
        if (type.isBlank() || type.equals("<unknown>") || isPrimitive(type)) {
            return Optional.empty();
        }
        if (type.contains(".")) {
            if (isKnownProjectType(type)) {
                return Optional.of(type);
            }
            Optional<String> samePackageNested = file.packageName()
                    .map(packageName -> packageName + "." + type)
                    .filter(nestedProjectTypeExists);
            return samePackageNested.isPresent()
                    ? samePackageNested
                    : Optional.of(type);
        }
        Optional<String> enclosingMember = enclosingType
                .map(owner -> owner.enclosingTypeNames().isEmpty()
                        ? owner.name()
                        : String.join(".", owner.enclosingTypeNames()))
                .map(ownerName -> ownerName + "." + type)
                .map(name -> file.packageName().map(packageName -> packageName + "." + name)
                        .orElse(name))
                .filter(exactNestedProjectTypeExists);
        if (enclosingMember.isPresent()) {
            return enclosingMember;
        }
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        for (String imported : file.imports()) {
            if (imported.startsWith("static ")) {
                continue;
            }
            if (!imported.endsWith(".*") && imported.endsWith("." + type)) {
                candidates.add(imported);
            }
        }
        if (candidates.size() == 1) {
            return Optional.of(candidates.getFirst());
        }
        if (!candidates.isEmpty()) {
            return Optional.empty();
        }

        if (IMPLICIT_JAVA_LANG_TYPES.contains(type)) {
            return Optional.of("java.lang." + type);
        }

        Optional<String> samePackage = file.packageName()
                .map(packageName -> packageName + "." + type)
                .filter(this::isKnownProjectType);
        if (samePackage.isPresent()) {
            return samePackage;
        }
        if (file.packageName().isEmpty()
                && file.types().stream().anyMatch(candidate -> candidate.name().equals(type))) {
            return Optional.of(type);
        }

        List<String> wildcardCandidates = file.imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .filter(imported -> imported.endsWith(".*"))
                .map(imported -> imported.substring(0, imported.length() - 2))
                .map(packageName -> packageName + "." + type)
                .filter(this::isKnownProjectType)
                .distinct()
                .toList();
        if (wildcardCandidates.size() == 1) {
            return Optional.of(wildcardCandidates.getFirst());
        }
        return Optional.empty();
    }

    /** Qualifies a declared type while retaining array dimensions for overload filtering. */
    public Optional<String> qualifyTypeShape(String declaredType) {
        String value = Objects.requireNonNull(declaredType, "declaredType").trim();
        int dimensions = 0;
        while (value.endsWith("[]")) {
            dimensions++;
            value = value.substring(0, value.length() - 2).trim();
        }
        if (value.endsWith("...")) {
            dimensions++;
            value = value.substring(0, value.length() - 3).trim();
        }
        String suffix = "[]".repeat(dimensions);
        if (isPrimitive(baseType(value))) {
            return Optional.of(baseType(value) + suffix);
        }
        return qualifyType(value).map(qualified -> qualified + suffix);
    }

    public Optional<String> qualifyAnnotation(String annotationName) {
        return qualifyType(annotationName);
    }

    public boolean annotationMatches(String annotationName, String expectedFqn) {
        String normalized = baseType(annotationName);
        if (normalized.equals(expectedFqn)) {
            return true;
        }
        if (!normalized.equals(simpleName(expectedFqn))) {
            return false;
        }
        List<String> explicitCandidates = file.imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .filter(imported -> imported.endsWith("." + normalized))
                .toList();
        if (!explicitCandidates.isEmpty()) {
            return explicitCandidates.size() == 1 && explicitCandidates.getFirst().equals(expectedFqn);
        }
        String expectedPackage = expectedFqn.substring(0, expectedFqn.lastIndexOf('.'));
        List<String> wildcardPackages = file.imports().stream()
                .filter(imported -> !imported.startsWith("static "))
                .filter(imported -> imported.endsWith(".*"))
                .map(imported -> imported.substring(0, imported.length() - 2))
                .toList();
        return wildcardPackages.size() == 1 && wildcardPackages.getFirst().equals(expectedPackage);
    }

    private static String baseType(String declaredType) {
        String result = Objects.requireNonNull(declaredType, "declaredType").trim();
        int genericStart = result.indexOf('<');
        if (genericStart >= 0) {
            result = result.substring(0, genericStart);
        }
        while (result.endsWith("[]")) {
            result = result.substring(0, result.length() - 2).trim();
        }
        if (result.endsWith("...")) {
            result = result.substring(0, result.length() - 3).trim();
        }
        return result;
    }

    private static String simpleName(String name) {
        int separator = name.lastIndexOf('.');
        return separator < 0 ? name : name.substring(separator + 1);
    }

    private static boolean isPrimitive(String name) {
        return switch (name) {
            case "boolean", "byte", "short", "int", "long", "char", "float", "double", "void" -> true;
            default -> false;
        };
    }

    private boolean isKnownProjectType(String qualifiedName) {
        if (projectTypeExists.test(qualifiedName)) {
            return true;
        }
        return file.types().stream().anyMatch(candidate -> {
            String declared = file.packageName()
                    .map(packageName -> packageName + "." + candidate.sourceName())
                    .orElse(candidate.sourceName());
            return declared.equals(qualifiedName);
        });
    }

    private static boolean isExactSupportedNestedType(
            ProjectTypeLookup projectTypes, String qualifiedName) {
        if (projectTypes.isAmbiguous(qualifiedName)) {
            return false;
        }
        List<ProjectTypeDeclaration> declarations = projectTypes.declarations(qualifiedName);
        if (declarations.size() != 1) {
            return false;
        }
        ProjectTypeDeclaration declaration = declarations.getFirst();
        ClassInfo nestedType = declaration.type();
        if (nestedType.enclosingTypeNames().size() != 1
                || (nestedType.kind() != TypeKind.RECORD && nestedType.kind() != TypeKind.ENUM)) {
            return false;
        }
        String ownerName = nestedType.enclosingTypeNames().getFirst();
        String ownerQualifiedName = declaration.file().packageName()
                .map(packageName -> packageName + "." + ownerName)
                .orElse(ownerName);
        return !projectTypes.isAmbiguous(ownerQualifiedName)
                && projectTypes.declarations(ownerQualifiedName).size() == 1;
    }
}
