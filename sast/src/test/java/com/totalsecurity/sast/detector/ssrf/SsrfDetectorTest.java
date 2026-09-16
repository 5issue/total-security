package com.totalsecurity.sast.detector.ssrf;

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
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SpringRestTemplateNetworkSinkRule;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SsrfDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final SsrfDetector DETECTOR = new SsrfDetector();
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
                    .filter(candidate -> candidate.name().equals("SsrfFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void supportedExternalInputTargetProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, sinkTaint(analysis));
    }

    private static Stream<String> positiveFlows() {
        return Stream.of(
                "requestParam",
                "pathVariable",
                "requestBody",
                "requestHeader",
                "cookieValue",
                "servletSource",
                "localAssignment",
                "concatenatedTarget",
                "trimmedTarget",
                "uriCreate",
                "directUriCreate",
                "normalizedUri",
                "branch",
                "loop",
                "postForEntity",
                "put",
                "headForHeaders",
                "optionsForAllow",
                "patchForObject");
    }

    @ParameterizedTest
    @MethodSource("supportedRestTemplateApis")
    void supportedRestTemplateApisUseOnlyRequestTargetArgumentZero(
            String fixtureMethod, String expectedSinkMethod) {
        SinkMatch sink = only(analyze(fixtureMethod).result().sinkMatches());
        assertEquals(SpringRestTemplateNetworkSinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.NETWORK_REQUEST_TARGET, sink.category());
        assertEquals(expectedSinkMethod, sink.call().call().methodName());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
    }

    private static Stream<Arguments> supportedRestTemplateApis() {
        return Stream.of(
                Arguments.of("requestParam", "getForObject"),
                Arguments.of("pathVariable", "getForEntity"),
                Arguments.of("requestBody", "postForObject"),
                Arguments.of("postForEntity", "postForEntity"),
                Arguments.of("put", "put"),
                Arguments.of("servletSource", "delete"),
                Arguments.of("requestHeader", "exchange"),
                Arguments.of("cookieValue", "execute"),
                Arguments.of("headForHeaders", "headForHeaders"),
                Arguments.of("optionsForAllow", "optionsForAllow"),
                Arguments.of("patchForObject", "patchForObject"));
    }

    @Test
    void uriCreateAndNormalizePreserveTaintAndProvenance() {
        Finding created = only(analyze("uriCreate").findings());
        Finding normalized = only(analyze("normalizedUri").findings());
        assertTrue(created.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of create")));
        assertTrue(normalized.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of normalize")));
    }

    @Test
    void directUriCreateHasKnownUriTypeAtOuterSink() {
        Analysis analysis = analyze("directUriCreate");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertEquals(SinkCategory.NETWORK_REQUEST_TARGET, sink.category());
        assertEquals(TaintState.TAINTED, analysis.result().sinkArgumentTaint(sink, 0).state());
    }

    @ParameterizedTest
    @MethodSource("cleanTargets")
    void fixedRequestTargetIsClean(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    private static Stream<String> cleanTargets() {
        return Stream.of("fixedString", "fixedUri", "cleanOverwrite");
    }

    @Test
    void sourceWithoutNetworkSinkProducesNoFinding() {
        Analysis analysis = analyze("sourceWithoutSink");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("customClients")
    void customClientApisDoNotMatch(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    private static Stream<String> customClients() {
        return Stream.of("customRestTemplate", "customHttpClient");
    }

    @ParameterizedTest
    @MethodSource("unknownTargetBuilders")
    void unmodeledTargetBuilderIsUnknownAndNotConfirmed(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.UNKNOWN, sinkTaint(analysis));
    }

    private static Stream<String> unknownTargetBuilders() {
        return Stream.of("customUriFactory", "unknownBuilder");
    }

    @Test
    void taintedPostBodyDoesNotTaintCleanTarget() {
        Analysis analysis = analyze("taintedBodyOnly");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 0).state());
        assertEquals(TaintState.TAINTED,
                analysis.result().taintResult().argumentTaint(sink.call(), 1).state());
    }

    @Test
    void taintedUriTemplateVariableDoesNotTaintCleanTargetArgument() {
        Analysis analysis = analyze("taintedTemplateVariableOnly");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 0).state());
        assertEquals(TaintState.TAINTED,
                analysis.result().taintResult().argumentTaint(sink.call(), 2).state());
    }

    @ParameterizedTest
    @MethodSource("unsupportedClientFlows")
    void unsupportedClientFlowProducesNoConfirmedFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    private static Stream<String> unsupportedClientFlows() {
        return Stream.of("ordinaryMethod", "webClientFlow", "httpClientFlow");
    }

    @Test
    void findingMetadataAndEvidenceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals(SsrfDetector.RULE_ID, finding.ruleId());
        assertEquals("Server-Side Request Forgery", finding.vulnerabilityType());
        assertEquals("CWE-918", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(SpringRestTemplateNetworkSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.NETWORK_REQUEST_TARGET, finding.sink().category());
        assertEquals("getForObject", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertTrue(finding.evidence().contains("supported outbound network request target"));
        assertFalse(finding.evidence().contains("guaranteed"));
    }

    @Test
    void sourceEvidenceAndUriConstructionFlowArePreserved() {
        Finding finding = only(analyze("uriCreate").findings());
        assertEquals("SPRING_MVC_REQUEST_PARAM", finding.sources().getFirst().sourceRuleId());
        assertFalse(finding.sources().getFirst().evidence().isBlank());
        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of create")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().startsWith("Definition of uri")));
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
        var resource = SsrfDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/SsrfFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 11 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
