package com.totalsecurity.sast.runner;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Conservative discovery of conventional Java source roots under one local project root. */
public final class ProjectJavaSourceDiscovery {
    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of(
            ".git", ".gradle", ".gradle-user-home", "build", "target", "out",
            "node_modules", ".idea", "generated");

    public ProjectJavaSourceDiscoveryResult discover(ProjectScanRequest request) {
        Path projectRoot = request.projectRoot().toAbsolutePath().normalize();
        List<ProjectScanDiagnostic> diagnostics = new ArrayList<>();
        if (!Files.isDirectory(projectRoot)) {
            diagnostics.add(diagnostic(
                    null, "Project root is not a readable directory", true));
            return new ProjectJavaSourceDiscoveryResult(
                    projectRoot, List.of(), List.of(), diagnostics);
        }

        Path realRoot;
        try {
            realRoot = projectRoot.toRealPath();
        } catch (IOException exception) {
            diagnostics.add(diagnostic(
                    null, "Cannot resolve project root: " + safeMessage(exception), true));
            return new ProjectJavaSourceDiscoveryResult(
                    projectRoot, List.of(), List.of(), diagnostics);
        }

        LinkedHashSet<Path> roots = new LinkedHashSet<>();
        if (request.sourceRoots().isEmpty()) {
            discoverConventionalRoots(projectRoot, request.includeTests(), roots, diagnostics);
        } else {
            for (Path configured : request.sourceRoots()) {
                Path candidate = configured.isAbsolute()
                        ? configured.toAbsolutePath().normalize()
                        : projectRoot.resolve(configured).normalize();
                if (!candidate.startsWith(projectRoot)) {
                    diagnostics.add(diagnostic(
                            configured, "Configured source root escapes projectRoot", true));
                    continue;
                }
                try {
                    if (!Files.isDirectory(candidate)
                            || Files.isSymbolicLink(candidate)
                            || !candidate.toRealPath().startsWith(realRoot)) {
                        diagnostics.add(diagnostic(
                                relative(projectRoot, candidate),
                                "Configured source root is missing, linked, or outside projectRoot",
                                true));
                        continue;
                    }
                    roots.add(candidate);
                } catch (IOException exception) {
                    diagnostics.add(diagnostic(
                            relative(projectRoot, candidate),
                            "Cannot resolve configured source root: " + safeMessage(exception),
                            true));
                }
            }
        }

        if (roots.isEmpty() && diagnostics.stream().noneMatch(ProjectScanDiagnostic::fatal)) {
            diagnostics.add(diagnostic(
                    null, "No conventional src/main/java source root was found", false));
        }

        List<Path> sortedRoots = roots.stream()
                .sorted(pathComparator(projectRoot))
                .toList();
        LinkedHashSet<Path> files = new LinkedHashSet<>();
        for (Path sourceRoot : sortedRoots) {
            collectJavaFiles(projectRoot, realRoot, sourceRoot, files, diagnostics);
        }
        return new ProjectJavaSourceDiscoveryResult(
                projectRoot,
                sortedRoots,
                files.stream().sorted(pathComparator(projectRoot)).toList(),
                List.copyOf(diagnostics));
    }

    private static void discoverConventionalRoots(
            Path projectRoot,
            boolean includeTests,
            Set<Path> roots,
            List<ProjectScanDiagnostic> diagnostics) {
        try {
            Files.walkFileTree(projectRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (!dir.equals(projectRoot)
                            && (Files.isSymbolicLink(dir) || excluded(dir))) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    if (isSourceRoot(projectRoot.relativize(dir), includeTests)) {
                        roots.add(dir.toAbsolutePath().normalize());
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exception) {
                    diagnostics.add(diagnostic(
                            relative(projectRoot, file),
                            "Cannot inspect path: " + safeMessage(exception),
                            false));
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException exception) {
            diagnostics.add(diagnostic(
                    null, "Source-root discovery failed: " + safeMessage(exception), true));
        }
    }

    private static void collectJavaFiles(
            Path projectRoot,
            Path realRoot,
            Path sourceRoot,
            Set<Path> files,
            List<ProjectScanDiagnostic> diagnostics) {
        try {
            Files.walkFileTree(sourceRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (!dir.equals(sourceRoot)
                            && (Files.isSymbolicLink(dir) || excluded(dir))) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile()
                            || Files.isSymbolicLink(file)
                            || !file.getFileName().toString().toLowerCase(Locale.ROOT)
                                    .endsWith(".java")) {
                        return FileVisitResult.CONTINUE;
                    }
                    try {
                        if (file.toRealPath().startsWith(realRoot)) {
                            files.add(file.toAbsolutePath().normalize());
                        } else {
                            diagnostics.add(diagnostic(
                                    relative(projectRoot, file),
                                    "Discovered source resolves outside projectRoot",
                                    true));
                        }
                    } catch (IOException exception) {
                        diagnostics.add(diagnostic(
                                relative(projectRoot, file),
                                "Cannot resolve source file: " + safeMessage(exception),
                                false));
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exception) {
                    diagnostics.add(diagnostic(
                            relative(projectRoot, file),
                            "Cannot inspect source path: " + safeMessage(exception),
                            false));
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException exception) {
            diagnostics.add(diagnostic(
                    relative(projectRoot, sourceRoot),
                    "Source traversal failed: " + safeMessage(exception),
                    false));
        }
    }

    private static boolean isSourceRoot(Path relative, boolean includeTests) {
        int count = relative.getNameCount();
        if (count < 3 || !relative.getName(count - 1).toString().equals("java")) {
            return false;
        }
        String scope = relative.getName(count - 2).toString();
        return relative.getName(count - 3).toString().equals("src")
                && (scope.equals("main") || includeTests && scope.equals("test"));
    }

    private static boolean excluded(Path directory) {
        Path name = directory.getFileName();
        return name != null
                && EXCLUDED_DIRECTORIES.contains(name.toString().toLowerCase(Locale.ROOT));
    }

    private static Comparator<Path> pathComparator(Path projectRoot) {
        return Comparator.comparing(path -> sortable(relative(projectRoot, path)));
    }

    private static String sortable(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static Path relative(Path projectRoot, Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return normalized.startsWith(projectRoot) ? projectRoot.relativize(normalized) : path;
    }

    private static ProjectScanDiagnostic diagnostic(Path path, String message, boolean fatal) {
        return new ProjectScanDiagnostic(
                java.util.Optional.ofNullable(path), ProjectScanStage.DISCOVERY, message, fatal);
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank()
                ? exception.getClass().getSimpleName()
                : message.replace('\r', ' ').replace('\n', ' ');
    }
}
