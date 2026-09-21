package com.totalsecurity.sast.runner;

import com.totalsecurity.sast.detector.deserialization.InsecureDeserializationDetector;
import com.totalsecurity.sast.detector.redirect.OpenRedirectDetector;
import com.totalsecurity.sast.detector.upload.UnrestrictedFileUploadDetector;
import com.totalsecurity.sast.detector.xss.XssDetector;
import com.totalsecurity.sast.detector.xxe.XxeDetector;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.FindingResult;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralAnalysis;
import com.totalsecurity.sast.interprocedural.CrossClassInterproceduralResult;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.interprocedural.ProjectMethodId;
import com.totalsecurity.sast.interprocedural.UnsupportedInterproceduralFlow;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.pattern.PatternAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.context.LombokGetterNamingContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/** One-shot external-path Java project scanner using the existing parsing and analysis layers. */
public final class ProjectScanner {
    private final ProjectJavaSourceDiscovery discovery;
    private final RuleRegistry rules;
    private final PatternAnalysis patterns;

    public ProjectScanner(
            ProjectJavaSourceDiscovery discovery,
            RuleRegistry rules,
            PatternAnalysis patterns) {
        this.discovery = Objects.requireNonNull(discovery, "discovery");
        this.rules = Objects.requireNonNull(rules, "rules");
        this.patterns = Objects.requireNonNull(patterns, "patterns");
    }

    public static ProjectScanner javaDefaults() {
        return new ProjectScanner(
                new ProjectJavaSourceDiscovery(),
                RuleRegistry.javaSpringBackendDefaults(),
                PatternAnalysis.javaDefaults());
    }

    public ProjectScanResult scan(Path projectRoot) {
        return scan(ProjectScanRequest.productionJava(projectRoot));
    }

    public ProjectScanResult scan(ProjectScanRequest request) {
        Objects.requireNonNull(request, "request");
        ProjectJavaSourceDiscoveryResult discovered = discovery.discover(request);
        Path projectRoot = discovered.projectRoot();
        List<ProjectScanDiagnostic> diagnostics = new ArrayList<>(discovered.diagnostics());
        if (diagnostics.stream().anyMatch(ProjectScanDiagnostic::fatal)) {
            return result(
                    projectRoot,
                    discovered.javaFiles(),
                    List.of(),
                    List.of(),
                    diagnostics,
                    List.of(),
                    List.of());
        }

        List<Path> parsedPaths = new ArrayList<>();
        List<Path> extractedPaths = new ArrayList<>();
        List<JavaFileInfo> extractedFiles = new ArrayList<>();
        parseAndExtract(
                request,
                projectRoot,
                discovered.javaFiles(),
                parsedPaths,
                extractedPaths,
                extractedFiles,
                diagnostics);
        LombokGetterNamingContext lombokNaming =
                new LombokConfigurationDiscovery().inspect(discovered.javaFiles());

        List<FindingResult> findings = new ArrayList<>();
        for (JavaFileInfo file : extractedFiles) {
            try {
                findings.addAll(patterns.analyze(file));
            } catch (RuntimeException exception) {
                diagnostics.add(diagnostic(
                        projectRoot,
                        file.location().file(),
                        ProjectScanStage.ANALYSIS,
                        "Pattern analysis failed: " + safeMessage(exception),
                        false));
            }
        }

        List<UnsupportedInterproceduralFlow> unsupported = new ArrayList<>();
        if (!extractedFiles.isEmpty()) {
            try {
                CrossClassInterproceduralResult cross =
                        new CrossClassInterproceduralAnalysis()
                                .analyze(extractedFiles, rules, lombokNaming);
                findings.addAll(cross.findings());
                unsupported.addAll(cross.unsupported());
                addContextSensitiveFindings(
                        projectRoot, extractedFiles, cross, lombokNaming, findings, diagnostics);
            } catch (RuntimeException exception) {
                diagnostics.add(diagnostic(
                        projectRoot,
                        null,
                        ProjectScanStage.ANALYSIS,
                        "Project analysis failed: " + safeMessage(exception),
                        true));
            }
        }

        return result(
                projectRoot,
                discovered.javaFiles(),
                parsedPaths,
                extractedPaths,
                diagnostics,
                findings,
                unsupported);
    }

    private static void parseAndExtract(
            ProjectScanRequest request,
            Path projectRoot,
            List<Path> files,
            List<Path> parsedPaths,
            List<Path> extractedPaths,
            List<JavaFileInfo> extractedFiles,
            List<ProjectScanDiagnostic> diagnostics) {
        JavaSourceParser parser;
        try {
            parser = new JavaSourceParser();
        } catch (RuntimeException exception) {
            diagnostics.add(diagnostic(
                    projectRoot,
                    null,
                    ProjectScanStage.PARSE,
                    "Tree-sitter Java initialization failed: " + safeMessage(exception),
                    true));
            return;
        }

        try (parser) {
            for (Path file : files) {
                try (ParsedJavaFile parsed = parser.parse(file, request.charset())) {
                    if (parsed.hasSyntaxErrors()) {
                        diagnostics.add(diagnostic(
                                projectRoot,
                                file,
                                ProjectScanStage.PARSE,
                                "Tree-sitter reported syntax errors",
                                false));
                        continue;
                    }
                    parsedPaths.add(file);
                    try {
                        JavaFileInfo extracted = new JavaSemanticExtractor().extract(parsed);
                        extractedFiles.add(extracted);
                        extractedPaths.add(file);
                    } catch (RuntimeException exception) {
                        diagnostics.add(diagnostic(
                                projectRoot,
                                file,
                                ProjectScanStage.SEMANTIC_EXTRACTION,
                                "Semantic extraction failed: " + safeMessage(exception),
                                false));
                    }
                } catch (IOException exception) {
                    diagnostics.add(diagnostic(
                            projectRoot,
                            file,
                            ProjectScanStage.READ,
                            "Cannot read Java source: " + safeMessage(exception),
                            false));
                } catch (IllegalStateException exception) {
                    diagnostics.add(diagnostic(
                            projectRoot,
                            file,
                            ProjectScanStage.PARSE,
                            "Tree-sitter engine failure: " + safeMessage(exception),
                            true));
                    break;
                } catch (RuntimeException exception) {
                    diagnostics.add(diagnostic(
                            projectRoot,
                            file,
                            ProjectScanStage.PARSE,
                            "Java parse failed: " + safeMessage(exception),
                            false));
                }
            }
        }
    }

    private void addContextSensitiveFindings(
            Path projectRoot,
            List<JavaFileInfo> extractedFiles,
            CrossClassInterproceduralResult cross,
            LombokGetterNamingContext lombokNaming,
            List<FindingResult> findings,
            List<ProjectScanDiagnostic> diagnostics) {
        RuleAwareTaintAnalysis intraprocedural = new RuleAwareTaintAnalysis();
        IdentityHashMap<MethodInfo, DataFlowResult> dataFlowByMethod = new IdentityHashMap<>();
        cross.methodAnalyses().forEach((method, analysis) -> dataFlowByMethod.put(
                method.method(), analysis.taintResult().dataFlow()));

        for (JavaFileInfo file : extractedFiles) {
            for (ClassInfo type : file.types()) {
                for (MethodInfo method : type.methods()) {
                    if (method.body().isEmpty()) {
                        continue;
                    }
                    ProjectMethodId methodId = new ProjectMethodId(
                            ProjectClassIndex.qualifiedName(file, type), method);
                    DataFlowResult dataFlow = dataFlowByMethod.get(method);
                    if (dataFlow == null) {
                        try {
                            ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
                            dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
                            dataFlowByMethod.put(method, dataFlow);
                        } catch (RuntimeException exception) {
                            diagnostics.add(diagnostic(
                                    projectRoot,
                                    method.location().file(),
                                    ProjectScanStage.ANALYSIS,
                                    "Intraprocedural data-flow preparation failed for "
                                            + methodId.displayName() + ": "
                                            + safeMessage(exception),
                                    false));
                            continue;
                        }
                    }

                    RuleAwareTaintResult local;
                    try {
                        local = intraprocedural.analyze(
                                file, type, method, dataFlow, rules,
                                cross.classIndex(), lombokNaming);
                    } catch (RuntimeException exception) {
                        diagnostics.add(diagnostic(
                                projectRoot,
                                method.location().file(),
                                ProjectScanStage.ANALYSIS,
                                "Intraprocedural context preparation failed for "
                                        + methodId.displayName() + ": " + safeMessage(exception),
                                false));
                        continue;
                    }

                    DataFlowResult detectorDataFlow = dataFlow;
                    addDetector(
                            "XXE",
                            projectRoot,
                            methodId,
                            findings,
                            diagnostics,
                            () -> new XxeDetector().detect(
                                    file, type, method, detectorDataFlow));
                    addDetector(
                            "Open Redirect",
                            projectRoot,
                            methodId,
                            findings,
                            diagnostics,
                            () -> new OpenRedirectDetector().detect(local));
                    addDetector(
                            "Insecure Deserialization",
                            projectRoot,
                            methodId,
                            findings,
                            diagnostics,
                            () -> new InsecureDeserializationDetector().detect(
                                    file, type, method, local));
                    addDetector(
                            "XSS",
                            projectRoot,
                            methodId,
                            findings,
                            diagnostics,
                            () -> new XssDetector().detect(file, type, method, local));
                    addDetector(
                            "Unrestricted File Upload",
                            projectRoot,
                            methodId,
                            findings,
                            diagnostics,
                            () -> new UnrestrictedFileUploadDetector().detect(
                                    file, type, method, local));
                }
            }
        }
    }

    private static void addDetector(
            String detector,
            Path projectRoot,
            ProjectMethodId method,
            List<FindingResult> findings,
            List<ProjectScanDiagnostic> diagnostics,
            Supplier<? extends List<? extends FindingResult>> operation) {
        try {
            findings.addAll(operation.get());
        } catch (RuntimeException exception) {
            diagnostics.add(diagnostic(
                    projectRoot,
                    method.method().location().file(),
                    ProjectScanStage.ANALYSIS,
                    detector + " analysis failed for " + method.displayName()
                            + ": " + safeMessage(exception),
                    false));
        }
    }

    private static ProjectScanResult result(
            Path projectRoot,
            List<Path> discovered,
            List<Path> parsed,
            List<Path> extracted,
            List<ProjectScanDiagnostic> diagnostics,
            List<FindingResult> findings,
            List<UnsupportedInterproceduralFlow> unsupported) {
        List<Path> relativeDiscovered = relativePaths(projectRoot, discovered);
        List<Path> relativeParsed = relativePaths(projectRoot, parsed);
        List<Path> relativeExtracted = relativePaths(projectRoot, extracted);
        List<ProjectScanDiagnostic> sortedDiagnostics = diagnostics.stream()
                .sorted(Comparator.comparing((ProjectScanDiagnostic item) -> item.stage().name())
                        .thenComparing(item -> item.path().map(ProjectScanner::sortable).orElse(""))
                        .thenComparing(ProjectScanDiagnostic::message))
                .toList();
        List<FindingResult> sortedFindings = deduplicateAndSort(projectRoot, findings);
        List<UnsupportedInterproceduralFlow> sortedUnsupported = unsupported.stream()
                .distinct()
                .sorted(Comparator.comparing((UnsupportedInterproceduralFlow item) ->
                                pathKey(projectRoot, item.location().file()))
                        .thenComparingInt(item -> item.location().startLine())
                        .thenComparing(item -> item.reason().name()))
                .toList();
        ProjectScanStatus status = sortedDiagnostics.stream().anyMatch(ProjectScanDiagnostic::fatal)
                ? ProjectScanStatus.FAILED
                : sortedDiagnostics.isEmpty() ? ProjectScanStatus.COMPLETE : ProjectScanStatus.PARTIAL;
        ProjectScanSummary summary = new ProjectScanSummary(
                relativeDiscovered.size(),
                relativeParsed.size(),
                relativeExtracted.size(),
                sortedDiagnostics.size(),
                sortedFindings.size(),
                sortedUnsupported.size());
        return new ProjectScanResult(
                projectRoot,
                status,
                relativeDiscovered,
                relativeParsed,
                relativeExtracted,
                sortedDiagnostics,
                sortedFindings,
                sortedUnsupported,
                summary);
    }

    private static List<FindingResult> deduplicateAndSort(
            Path projectRoot, List<FindingResult> findings) {
        Comparator<FindingResult> comparator = Comparator
                .comparing((FindingResult finding) ->
                        pathKey(projectRoot, finding.primaryLocation().file()))
                .thenComparingInt(finding -> finding.primaryLocation().startLine())
                .thenComparingInt(finding -> finding.primaryLocation().startColumn())
                .thenComparing(FindingResult::ruleId)
                .thenComparing(finding -> finding.getClass().getName());
        LinkedHashMap<FindingIdentity, FindingResult> unique = new LinkedHashMap<>();
        findings.stream().sorted(comparator).forEach(finding -> unique.putIfAbsent(
                new FindingIdentity(
                        finding.getClass().getName(),
                        finding.ruleId(),
                        finding.primaryLocation()),
                finding));
        return List.copyOf(unique.values());
    }

    private static List<Path> relativePaths(Path root, List<Path> paths) {
        return paths.stream()
                .map(path -> root.relativize(path.toAbsolutePath().normalize()))
                .sorted(Comparator.comparing(ProjectScanner::sortable))
                .toList();
    }

    private static String pathKey(Path root, Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return sortable(normalized.startsWith(root) ? root.relativize(normalized) : normalized);
    }

    private static String sortable(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static ProjectScanDiagnostic diagnostic(
            Path root,
            Path file,
            ProjectScanStage stage,
            String message,
            boolean fatal) {
        Optional<Path> path = Optional.ofNullable(file).map(value -> {
            Path normalized = value.toAbsolutePath().normalize();
            return normalized.startsWith(root) ? root.relativize(normalized) : value;
        });
        return new ProjectScanDiagnostic(path, stage, message, fatal);
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank()
                ? exception.getClass().getSimpleName()
                : message.replace('\r', ' ').replace('\n', ' ');
    }

    private record FindingIdentity(
            String resultType,
            String ruleId,
            com.totalsecurity.sast.ir.SourceLocation location) {}
}
