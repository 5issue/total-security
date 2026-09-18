package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.TypeKind;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Selects only source-proven, unique concrete class implementations of project interfaces. */
final class UniqueInterfaceImplementationResolver {
    private static final Set<String> SPRING_DATA_REPOSITORY_MARKERS = Set.of(
            "org.springframework.data.repository.Repository",
            "org.springframework.data.repository.CrudRepository",
            "org.springframework.data.repository.ListCrudRepository",
            "org.springframework.data.repository.PagingAndSortingRepository",
            "org.springframework.data.repository.ListPagingAndSortingRepository",
            "org.springframework.data.repository.reactive.ReactiveCrudRepository",
            "org.springframework.data.repository.reactive.ReactiveSortingRepository",
            "org.springframework.data.jpa.repository.JpaRepository");

    private final ProjectClassIndex index;

    UniqueInterfaceImplementationResolver(ProjectClassIndex index) {
        this.index = Objects.requireNonNull(index, "index");
    }

    Selection select(ProjectClassEntry projectInterface) {
        Objects.requireNonNull(projectInterface, "projectInterface");
        if (projectInterface.type().kind() != TypeKind.INTERFACE) {
            throw new IllegalArgumentException("projectInterface must be an interface");
        }

        Optional<ProjectClassEntry> proxy = springDataProxySubtype(projectInterface);
        if (proxy.isPresent()) {
            return Selection.unsupported(
                    "Spring Data repository proxy hierarchy "
                            + proxy.orElseThrow().qualifiedName()
                            + " is not a source concrete implementation");
        }

        Map<String, ProjectClassEntry> candidates = new LinkedHashMap<>();
        for (ProjectClassEntry entry : index.entries()) {
            if (entry.type().kind() == TypeKind.INTERFACE || entry.type().abstractType()) {
                continue;
            }
            if (!index.isDeclaredSubtypeOf(entry, projectInterface.qualifiedName())) {
                continue;
            }
            if (entry.type().kind() != TypeKind.CLASS) {
                return Selection.unsupported(
                        "Non-class implementation candidate is outside conservative interface "
                                + "dispatch scope: " + entry.qualifiedName());
            }
            if (index.candidates(entry.qualifiedName()).size() != 1) {
                return Selection.unsupported(
                        "Concrete implementation candidate has duplicate FQN "
                                + entry.qualifiedName());
            }
            candidates.put(entry.qualifiedName(), entry);
        }

        if (candidates.isEmpty()) {
            return Selection.unsupported(
                    "No unique analyzable concrete project implementation for "
                            + projectInterface.qualifiedName());
        }
        if (candidates.size() > 1) {
            return Selection.unsupported(
                    "Multiple concrete project implementations for "
                            + projectInterface.qualifiedName() + ": "
                            + String.join(", ", candidates.keySet()));
        }
        return Selection.resolved(candidates.values().iterator().next());
    }

    private Optional<ProjectClassEntry> springDataProxySubtype(
            ProjectClassEntry projectInterface) {
        return index.entries().stream()
                .filter(entry -> entry.type().kind() == TypeKind.INTERFACE)
                .filter(entry -> index.isDeclaredSubtypeOf(
                        entry, projectInterface.qualifiedName()))
                .filter(this::isSpringDataRepository)
                .findFirst();
    }

    private boolean isSpringDataRepository(ProjectClassEntry candidate) {
        return SPRING_DATA_REPOSITORY_MARKERS.stream()
                .anyMatch(marker -> index.isDeclaredSubtypeOf(candidate, marker));
    }

    record Selection(Optional<ProjectClassEntry> implementation, String detail) {
        Selection {
            implementation = Objects.requireNonNull(implementation, "implementation");
            if (detail == null || detail.isBlank()) {
                throw new IllegalArgumentException("detail must not be blank");
            }
        }

        static Selection resolved(ProjectClassEntry implementation) {
            return new Selection(
                    Optional.of(implementation),
                    "Unique source-proven concrete implementation "
                            + implementation.qualifiedName());
        }

        static Selection unsupported(String detail) {
            return new Selection(Optional.empty(), detail);
        }
    }
}
