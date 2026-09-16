package com.totalsecurity.sast.detector.path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingFlowStepKind;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.JavaNioFilesPathSinkRule;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.taint.TaintState;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;

class PathTraversalDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final PathTraversalDetector DETECTOR = new PathTraversalDetector();
    private static JavaFileInfo file;
    private static ClassInfo type;
    private static Map<String, MethodInfo> methods;

    @BeforeAll
    static void loadFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath())) {
            assertFalse(parsed.hasSyntaxErrors());
            file = new JavaSemanticExtractor().extract(parsed);
            type = file.types().stream()
                    .filter(candidate -> candidate.name().equals("PathTraversalFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("supportedPositiveFlows")
    void supportedExternalInputPathFlowProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, sinkTaint(analysis));
    }

    private static Stream<String> supportedPositiveFlows() {
        return Stream.of(
                "requestParam",
                "pathVariable",
                "servletSource",
                "localAssignment",
                "directNested",
                "resolve",
                "normalize",
                "toAbsolutePath",
                "branch",
                "loop",
                "writeTaintedPath",
                "deleteTaintedPath",
                "outputStreamTaintedPath",
                "deleteIfExistsTaintedPath");
    }

    @ParameterizedTest
    @MethodSource("supportedFilesApis")
    void supportedFilesApisUseOnlyPathArgumentZero(
            String fixtureMethod, String expectedSinkMethod) {
        SinkMatch sink = only(analyze(fixtureMethod).result().sinkMatches());
        assertEquals(JavaNioFilesPathSinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.FILESYSTEM_PATH, sink.category());
        assertEquals(expectedSinkMethod, sink.call().call().methodName());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
    }

    private static Stream<Arguments> supportedFilesApis() {
        return Stream.of(
                Arguments.of("requestParam", "readString"),
                Arguments.of("pathVariable", "readAllBytes"),
                Arguments.of("servletSource", "newInputStream"),
                Arguments.of("localAssignment", "newBufferedReader"),
                Arguments.of("writeTaintedPath", "writeString"),
                Arguments.of("outputStreamTaintedPath", "newOutputStream"),
                Arguments.of("deleteTaintedPath", "delete"),
                Arguments.of("deleteIfExistsTaintedPath", "deleteIfExists"));
    }

    @Test
    void pathOfAndPathsGetPropagateArgumentTaint() {
        Finding pathOf = only(analyze("requestParam").findings());
        Finding pathsGet = only(analyze("servletSource").findings());
        assertTrue(pathOf.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of of")));
        assertTrue(pathsGet.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of get")));
    }

    @Test
    void resolveCombinesCleanReceiverAndTaintedArgument() {
        Finding finding = only(analyze("resolve").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of resolve")));
    }

    @ParameterizedTest
    @MethodSource("receiverTransforms")
    void pathReceiverTransformPreservesTaint(String methodName, String transform) {
        Finding finding = only(analyze(methodName).findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of " + transform)));
    }

    private static Stream<Arguments> receiverTransforms() {
        return Stream.of(
                Arguments.of("normalize", "normalize"),
                Arguments.of("toAbsolutePath", "toAbsolutePath"));
    }

    @Test
    void fixedPathIsCleanAndProducesNoFinding() {
        Analysis analysis = analyze("fixedPath");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void sourceWithoutFilesystemSinkProducesNoFinding() {
        Analysis analysis = analyze("sourceWithoutSink");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void cleanPathOverwriteKillsTaintedDefinition() {
        Analysis analysis = analyze("cleanOverwrite");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @ParameterizedTest
    @MethodSource("customFilesMethods")
    void customFilesApiDoesNotMatch(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    private static Stream<String> customFilesMethods() {
        return Stream.of("customFiles", "customFilesClass");
    }

    @ParameterizedTest
    @MethodSource("unknownPathConstructionMethods")
    void unmodeledPathConstructionIsUnknownAndNotConfirmed(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.UNKNOWN, sinkTaint(analysis));
    }

    private static Stream<String> unknownPathConstructionMethods() {
        return Stream.of("customPathFactory", "unknownPathBuilder");
    }

    @Test
    void taintedContentAtWriteArgumentOneDoesNotTaintCleanPathArgumentZero() {
        Analysis analysis = analyze("taintedContentOnly");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 0).state());
        assertEquals(TaintState.TAINTED, analysis.result().taintResult().argumentTaint(sink.call(), 1).state());
    }

    @Test
    void ordinaryMethodWithTaintedPathIsNotFilesystemSink() {
        Analysis analysis = analyze("ordinaryMethod");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void findingMetadataAndSinkEvidenceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals(PathTraversalDetector.RULE_ID, finding.ruleId());
        assertEquals("Path Traversal", finding.vulnerabilityType());
        assertEquals("CWE-22", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(JavaNioFilesPathSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.FILESYSTEM_PATH, finding.sink().category());
        assertEquals("readString", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertTrue(finding.evidence().contains("filesystem Path argument 0"));
    }

    @Test
    void sourceEvidenceAndPathConstructionProvenanceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals("SPRING_MVC_REQUEST_PARAM", finding.sources().getFirst().sourceRuleId());
        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of of")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().startsWith("Definition of path")));
    }

    @Test
    void multipleSourcesAtOnePhysicalSinkProduceOneFindingWithAllOrigins() {
        Finding finding = only(analyze("multipleSources").findings());
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
        assertEquals(
                Set.of("SPRING_MVC_REQUEST_PARAM", "SPRING_MVC_REQUEST_HEADER"),
                finding.sources().stream().map(source -> source.sourceRuleId()).collect(Collectors.toSet()));
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        RuleAwareTaintResult result =
                new RuleAwareTaintAnalysis().analyze(file, type, method, dataFlow, RULES);
        return new Analysis(result, DETECTOR.detect(result));
    }

    private static TaintState sinkTaint(Analysis analysis) {
        SinkMatch sink = only(analysis.result().sinkMatches());
        return analysis.result().sinkArgumentTaint(sink, 0).state();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = PathTraversalDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/PathTraversalFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 10 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
