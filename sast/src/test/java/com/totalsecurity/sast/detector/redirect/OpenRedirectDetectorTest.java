package com.totalsecurity.sast.detector.redirect;

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
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.RuleAwareTaintAnalysis;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.RuleRegistry;
import com.totalsecurity.sast.rule.sink.JakartaServletRedirectSinkRule;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class OpenRedirectDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final OpenRedirectDetector DETECTOR = new OpenRedirectDetector();
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
                    .filter(candidate -> candidate.name().equals("OpenRedirectFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void fullyControlledSupportedRedirectProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, targetTaint(analysis));
        assertEquals(RedirectTargetControl.FULLY_CONTROLLED, targetControl(analysis));
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
                "throughTrim",
                "taintedPrefix",
                "branch",
                "loop",
                "multipleSources",
                "booleanOverload",
                "statusOverload",
                "statusAndBooleanOverload",
                "typedBooleanOverload",
                "emptyPrefix");
    }

    @ParameterizedTest
    @MethodSource("supportedOverloads")
    void exactJakartaSendRedirectOverloadsMatch(String methodName, int arity) {
        SinkMatch sink = only(analyze(methodName).result().sinkMatches());
        assertEquals(JakartaServletRedirectSinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.REDIRECT_TARGET, sink.category());
        assertEquals("sendRedirect", sink.call().call().methodName());
        assertEquals(arity, sink.call().call().arguments().size());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
    }

    private static Stream<Arguments> supportedOverloads() {
        return Stream.of(
                Arguments.of("requestParam", 1),
                Arguments.of("booleanOverload", 2),
                Arguments.of("typedBooleanOverload", 2),
                Arguments.of("statusOverload", 2),
                Arguments.of("statusAndBooleanOverload", 3));
    }

    @ParameterizedTest
    @MethodSource("fixedPrefixFlows")
    void fixedPrefixRemainsTaintedButIsNotAConfirmedFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(TaintState.TAINTED, targetTaint(analysis));
        assertEquals(RedirectTargetControl.FIXED_PREFIX, targetControl(analysis));
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> fixedPrefixFlows() {
        return Stream.of("fixedRelativePrefix", "nestedFixedPrefix", "fixedAbsolutePrefix");
    }

    @Test
    void cleanLiteralRedirectIsCleanAndNotReported() {
        Analysis analysis = analyze("fixedLiteral");
        assertEquals(TaintState.CLEAN, targetTaint(analysis));
        assertEquals(RedirectTargetControl.CLEAN, targetControl(analysis));
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void cleanOverwriteKillsTheControlledDefinition() {
        Analysis analysis = analyze("cleanOverwrite");
        assertEquals(TaintState.CLEAN, targetTaint(analysis));
        assertEquals(RedirectTargetControl.CLEAN, targetControl(analysis));
        assertTrue(analysis.findings().isEmpty());
    }

    @Test
    void unmodeledBuilderIsUnknownAndNotConfirmed() {
        Analysis analysis = analyze("unknownBuilder");
        assertEquals(TaintState.UNKNOWN, targetTaint(analysis));
        assertEquals(RedirectTargetControl.UNKNOWN, targetControl(analysis));
        assertTrue(analysis.findings().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("nonJakartaOrUnsupportedCalls")
    void nonJakartaOrUnsupportedCallsDoNotMatch(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.result().sinkMatches().isEmpty());
        assertTrue(analysis.findings().isEmpty());
    }

    private static Stream<String> nonJakartaOrUnsupportedCalls() {
        return Stream.of(
                "sourceWithoutSink",
                "customResponse",
                "customSender",
                "legacyResponse",
                "wrongSecondArgument",
                "wrongThreeArgumentOrder",
                "tooManyArguments",
                "ordinaryMethod",
                "locationHeaderOnly",
                "springRedirectReturn",
                "redirectViewFlow");
    }

    @ParameterizedTest
    @MethodSource("controlMerges")
    void controlLatticeUsesDocumentedMayAnalysisMerge(
            RedirectTargetControl left,
            RedirectTargetControl right,
            RedirectTargetControl expected) {
        assertEquals(expected, left.join(right));
        assertEquals(expected, right.join(left));
    }

    private static Stream<Arguments> controlMerges() {
        return Stream.of(
                Arguments.of(
                        RedirectTargetControl.CLEAN,
                        RedirectTargetControl.CLEAN,
                        RedirectTargetControl.CLEAN),
                Arguments.of(
                        RedirectTargetControl.CLEAN,
                        RedirectTargetControl.FIXED_PREFIX,
                        RedirectTargetControl.FIXED_PREFIX),
                Arguments.of(
                        RedirectTargetControl.FIXED_PREFIX,
                        RedirectTargetControl.FIXED_PREFIX,
                        RedirectTargetControl.FIXED_PREFIX),
                Arguments.of(
                        RedirectTargetControl.UNKNOWN,
                        RedirectTargetControl.CLEAN,
                        RedirectTargetControl.UNKNOWN),
                Arguments.of(
                        RedirectTargetControl.UNKNOWN,
                        RedirectTargetControl.FIXED_PREFIX,
                        RedirectTargetControl.UNKNOWN),
                Arguments.of(
                        RedirectTargetControl.UNKNOWN,
                        RedirectTargetControl.UNKNOWN,
                        RedirectTargetControl.UNKNOWN),
                Arguments.of(
                        RedirectTargetControl.FULLY_CONTROLLED,
                        RedirectTargetControl.CLEAN,
                        RedirectTargetControl.FULLY_CONTROLLED),
                Arguments.of(
                        RedirectTargetControl.FULLY_CONTROLLED,
                        RedirectTargetControl.FIXED_PREFIX,
                        RedirectTargetControl.FULLY_CONTROLLED),
                Arguments.of(
                        RedirectTargetControl.FULLY_CONTROLLED,
                        RedirectTargetControl.UNKNOWN,
                        RedirectTargetControl.FULLY_CONTROLLED),
                Arguments.of(
                        RedirectTargetControl.FULLY_CONTROLLED,
                        RedirectTargetControl.FULLY_CONTROLLED,
                        RedirectTargetControl.FULLY_CONTROLLED));
    }

    @Test
    void findingMetadataAndEvidenceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals(OpenRedirectDetector.RULE_ID, finding.ruleId());
        assertEquals("Open Redirect", finding.vulnerabilityType());
        assertEquals("CWE-601", finding.cwe());
        assertEquals(FindingSeverity.MEDIUM, finding.severity());
        assertEquals(JakartaServletRedirectSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.REDIRECT_TARGET, finding.sink().category());
        assertEquals("sendRedirect", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertEquals(
                "Tainted external input controls a supported HTTP redirect target.",
                finding.evidence());
        assertFalse(finding.evidence().contains("guaranteed"));
    }

    @Test
    void sourceToTrimToRedirectProvenanceIsPreserved() {
        Finding finding = only(analyze("throughTrim").findings());
        assertEquals("SPRING_MVC_REQUEST_PARAM", finding.sources().getFirst().sourceRuleId());
        assertFalse(finding.sources().getFirst().evidence().isBlank());
        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of trim")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().startsWith("Definition of target")));
    }

    @Test
    void multipleSourcesAtOnePhysicalSinkProduceOneFindingWithAllOrigins() {
        Finding finding = only(analyze("multipleSources").findings());
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
        assertEquals(
                Set.of("SPRING_MVC_REQUEST_PARAM", "SPRING_MVC_REQUEST_HEADER"),
                finding.sources().stream()
                        .map(source -> source.sourceRuleId())
                        .collect(Collectors.toSet()));
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        RuleAwareTaintResult result =
                new RuleAwareTaintAnalysis().analyze(file, type, method, dataFlow, RULES);
        return new Analysis(result, DETECTOR.detect(result));
    }

    private static TaintState targetTaint(Analysis analysis) {
        SinkMatch sink = only(analysis.result().sinkMatches());
        return analysis.result().sinkArgumentTaint(sink, 0).state();
    }

    private static RedirectTargetControl targetControl(Analysis analysis) {
        SinkMatch sink = only(analysis.result().sinkMatches());
        Expression target = sink.call().call().arguments().getFirst();
        return new RedirectTargetControlAnalysis(analysis.result()).classify(target);
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = OpenRedirectDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/OpenRedirectFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 14 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
