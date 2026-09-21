package com.totalsecurity.sast.rule.context;

import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

/** Conservative lookup of source-declared project types; duplicate FQNs remain visible. */
public interface ProjectTypeLookup {
    boolean contains(String qualifiedName);

    List<ProjectTypeDeclaration> declarations(String qualifiedName);

    default boolean isAmbiguous(String qualifiedName) {
        return false;
    }

    static ProjectTypeLookup none() {
        return existenceOnly(ignored -> false);
    }

    static ProjectTypeLookup existenceOnly(Predicate<String> exists) {
        Objects.requireNonNull(exists, "exists");
        return new ProjectTypeLookup() {
            @Override
            public boolean contains(String qualifiedName) {
                return exists.test(qualifiedName);
            }

            @Override
            public List<ProjectTypeDeclaration> declarations(String qualifiedName) {
                return List.of();
            }
        };
    }
}
