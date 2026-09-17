package com.totalsecurity.sast.detector.deserialization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.finding.DeserializationFinding;
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
import com.totalsecurity.sast.rule.source.ServletRequestSourceRule;
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

class InsecureDeserializationDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final InsecureDeserializationDetector DETECTOR =
            new InsecureDeserializationDetector();
    private static final JavaObjectDeserializationAnalyzer ANALYZER =
            new JavaObjectDeserializationAnalyzer();
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
                    .filter(candidate -> candidate.name().equals("InsecureDeserializationFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void supportedExternalInputLineageProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.uses().size());
        assertEquals(TaintState.TAINTED, only(analysis.uses()).inputState());
        assertEquals(1, analysis.findings().size());
    }

    private static Stream<String> positiveFlows() {
        return Stream.of(
                "requestBody",
                "directNested",
                "localByteArrayInputStream",
                "inputStreamSupertype",
                "buffered",
                "bufferedWithSize",
                "localByteAssignment",
                "servletInputStream",
                "branch",
                "loopWrapper",
                "multipleSources",
                "objectStreamAlias",
                "filterNotAssumedSafe");
    }

    @Test
    void nestedConstructionRetainsDistinctConstructionAndReadLocations() {
        DeserializationFinding finding = only(analyze("directNested").findings());
        assertEquals(1, finding.deserializerCreationLocations().size());
        assertNotEquals(
                finding.deserializerCreationLocations().getFirst(),
                finding.deserializationLocation());
    }

    @Test
    void bufferedWrappersAreRecordedInOrder() {
        DeserializationFinding finding = only(analyze("buffered").findings());
        List<String> apis = finding.lineage().stream().map(entry -> entry.api()).toList();
        assertTrue(apis.stream().anyMatch(api -> api.contains("ByteArrayInputStream.<init>")));
        assertTrue(apis.stream().anyMatch(api -> api.contains("BufferedInputStream.<init>")));
        assertTrue(apis.stream().anyMatch(api -> api.contains("ObjectInputStream.<init>")));
        assertTrue(apis.getLast().endsWith("ObjectInputStream.readObject()"));
    }

    @Test
    void servletInputStreamIsAnExactExpressionSource() {
        Analysis analysis = analyze("servletInputStream");
        DeserializationFinding finding = only(analysis.findings());
        assertEquals(ServletRequestSourceRule.ID, finding.sources().getFirst().sourceRuleId());
        assertTrue(finding.sources().getFirst().summary().contains("getInputStream"));
    }

    @Test
    void branchMayAnalysisRetainsTaintedAlternative() {
        NativeDeserializationUse use = only(analyze("branch").uses());
        assertEquals(TaintState.TAINTED, use.inputState());
        assertTrue(use.lineages().stream()
                .anyMatch(lineage -> lineage.inputTaint().state() == TaintState.CLEAN));
        assertTrue(use.lineages().stream()
                .anyMatch(lineage -> lineage.inputTaint().state() == TaintState.TAINTED));
    }

    @Test
    void multipleOriginsProduceOneFindingAndAllSourceEvidence() {
        Analysis analysis = analyze("multipleSources");
        DeserializationFinding finding = only(analysis.findings());
        assertEquals(1, analysis.uses().size());
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
        assertEquals(
                Set.of("SPRING_MVC_REQUEST_BODY", "SPRING_MVC_REQUEST_HEADER"),
                finding.sources().stream()
                        .map(source -> source.sourceRuleId())
                        .collect(Collectors.toSet()));
    }

    @Test
    void objectInputFilterNameDoesNotSuppressFinding() {
        Analysis analysis = analyze("filterNotAssumedSafe");
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, only(analysis.uses()).inputState());
    }

    @Test
    void cleanInternalBytesProduceNoFinding() {
        Analysis analysis = analyze("cleanInput");
        assertEquals(TaintState.CLEAN, only(analysis.uses()).inputState());
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void cleanOverwriteKillsExternalByteDefinition() {
        Analysis analysis = analyze("cleanOverwrite");
        assertEquals(TaintState.CLEAN, only(analysis.uses()).inputState());
        assertTrue(analysis.findings().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("noReadObjectUses")
    void sourceWithoutExactReadObjectProducesNoUseOrFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.uses().isEmpty());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> noReadObjectUses() {
        return Stream.of(
                "sourceWithoutReadObject",
                "objectStreamCreationOnly",
                "readUnsharedOnly",
                "customObjectInputStream",
                "customReadObject",
                "arbitraryDeserialize",
                "jackson",
                "dataInput");
    }

    @ParameterizedTest
    @MethodSource("unknownLineages")
    void unknownObjectOrInputLineageIsNotConfirmed(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(TaintState.UNKNOWN, only(analysis.uses()).inputState());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> unknownLineages() {
        return Stream.of("unknownStreamBuilder", "unknownReceiver", "customRequest");
    }

    @Test
    void customRequestGetInputStreamIsNotASource() {
        Analysis analysis = analyze("customRequest");
        assertTrue(analysis.result().sourceMatches().isEmpty());
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void findingMetadataAndLineageEvidenceAreExact() {
        DeserializationFinding finding = only(analyze("requestBody").findings());
        assertEquals(InsecureDeserializationDetector.RULE_ID, finding.ruleId());
        assertEquals("Insecure Deserialization", finding.vulnerabilityType());
        assertEquals("CWE-502", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(
                JavaObjectDeserializationAnalyzer.OBJECT_INPUT_STREAM,
                finding.deserializerType());
        assertEquals(finding.primaryLocation(), finding.deserializationLocation());
        assertEquals(InsecureDeserializationDetector.EVIDENCE, finding.evidence());
        assertFalse(finding.evidence().contains("guaranteed"));
        assertTrue(finding.lineage().stream()
                .anyMatch(entry -> entry.api().endsWith("ObjectInputStream.readObject()")));
    }

    @Test
    void sourceConstructorAndReadObjectFlowArePreserved() {
        DeserializationFinding finding = only(analyze("requestBody").findings());
        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().contains("Byte array converted")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().contains("object-input stream construction")));
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        RuleAwareTaintResult result =
                new RuleAwareTaintAnalysis().analyze(file, type, method, dataFlow, RULES);
        List<NativeDeserializationUse> uses = ANALYZER.analyze(file, type, method, result);
        return new Analysis(result, uses, DETECTOR.detect(file, type, method, result));
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = InsecureDeserializationDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/InsecureDeserializationFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 15 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(
            RuleAwareTaintResult result,
            List<NativeDeserializationUse> uses,
            List<DeserializationFinding> findings) {}
}
