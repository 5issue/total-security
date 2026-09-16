package com.totalsecurity.sast.detector.ldap;

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
import com.totalsecurity.sast.rule.sink.JndiLdapFilterSinkRule;
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

class LdapInjectionDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final LdapInjectionDetector DETECTOR = new LdapInjectionDetector();
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
                    .filter(candidate -> candidate.name().equals("LdapInjectionFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("positiveFlows")
    void supportedExternalInputFilterProducesFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, filterTaint(analysis));
    }

    private static Stream<String> positiveFlows() {
        return Stream.of(
                "requestParam",
                "pathVariable",
                "requestBody",
                "requestHeader",
                "cookieValue",
                "servletSource",
                "directBinary",
                "localAssignment",
                "throughTrim",
                "branch",
                "loop",
                "parameterizedFilterExpr",
                "nameBase",
                "initialDirContext",
                "ldapContext",
                "initialLdapContext");
    }

    @ParameterizedTest
    @MethodSource("supportedReceivers")
    void supportedReceiverFqnMatches(String methodName) {
        SinkMatch sink = only(analyze(methodName).result().sinkMatches());
        assertEquals(JndiLdapFilterSinkRule.ID, sink.ruleId());
        assertEquals(SinkCategory.LDAP_FILTER, sink.category());
        assertEquals("search", sink.call().call().methodName());
        assertEquals(Set.of(1), sink.sensitiveArgumentIndexes());
    }

    private static Stream<String> supportedReceivers() {
        return Stream.of("requestParam", "initialDirContext", "ldapContext", "initialLdapContext");
    }

    @ParameterizedTest
    @MethodSource("supportedOverloads")
    void supportedOverloadStructuresMatch(String methodName, int arity) {
        SinkMatch sink = only(analyze(methodName).result().sinkMatches());
        assertEquals(arity, sink.call().call().arguments().size());
        assertEquals(Set.of(1), sink.sensitiveArgumentIndexes());
    }

    private static Stream<Arguments> supportedOverloads() {
        return Stream.of(
                Arguments.of("requestParam", 3),
                Arguments.of("nameBase", 3),
                Arguments.of("parameterizedFilterExpr", 4));
    }

    @Test
    void binaryFilterConstructionIsPresentInProvenance() {
        Finding finding = only(analyze("requestParam").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Binary expression +")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().startsWith("Definition of filter")));
    }

    @Test
    void trimPreservesFilterTaint() {
        Finding finding = only(analyze("throughTrim").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of trim")));
    }

    @ParameterizedTest
    @MethodSource("cleanFilterMethods")
    void cleanFilterProducesNoFinding(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, filterTaint(analysis));
    }

    private static Stream<String> cleanFilterMethods() {
        return Stream.of("fixedFilter", "cleanOverwrite", "taintedBaseOnly");
    }

    @Test
    void sourceWithoutLdapSinkProducesNoFinding() {
        Analysis analysis = analyze("sourceWithoutSink");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("customSearchMethods")
    void customSearchApiDoesNotMatch(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    private static Stream<String> customSearchMethods() {
        return Stream.of("customDirContext", "customDirectory", "springLdapTemplate");
    }

    @Test
    void attributesSearchOverloadDoesNotMatch() {
        Analysis analysis = analyze("attributesOverload");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void parameterizedFilterArgsAreNotRawFilterSinkPosition() {
        Analysis analysis = analyze("parameterizedArgsOnly");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 1).state());
        assertEquals(TaintState.TAINTED,
                analysis.result().taintResult().argumentTaint(sink.call(), 2).state());
    }

    @Test
    void taintedBaseNameIsNotLdapFilterPosition() {
        Analysis analysis = analyze("taintedBaseOnly");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.TAINTED,
                analysis.result().taintResult().argumentTaint(sink.call(), 0).state());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 1).state());
    }

    @Test
    void unmodeledFilterBuilderIsUnknownAndNotConfirmed() {
        Analysis analysis = analyze("unknownBuilder");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.UNKNOWN, filterTaint(analysis));
    }

    @Test
    void ordinaryMethodWithTaintedValueIsNotLdapSink() {
        Analysis analysis = analyze("ordinaryMethod");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void findingMetadataAndSinkEvidenceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals(LdapInjectionDetector.RULE_ID, finding.ruleId());
        assertEquals("LDAP Injection", finding.vulnerabilityType());
        assertEquals("CWE-90", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(JndiLdapFilterSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.LDAP_FILTER, finding.sink().category());
        assertEquals("search", finding.sink().methodName());
        assertEquals(1, finding.sink().argumentIndex());
        assertTrue(finding.evidence().contains("supported LDAP search-filter argument 1"));
        assertFalse(finding.evidence().contains("guaranteed"));
    }

    @Test
    void sourceEvidenceAndOrderedFlowArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals("SPRING_MVC_REQUEST_PARAM", finding.sources().getFirst().sourceRuleId());
        assertFalse(finding.sources().getFirst().evidence().isBlank());
        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
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

    private static TaintState filterTaint(Analysis analysis) {
        SinkMatch sink = only(analysis.result().sinkMatches());
        return analysis.result().sinkArgumentTaint(sink, 1).state();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = LdapInjectionDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/LdapInjectionFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 12 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
