package com.totalsecurity.sast.detector.command;

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
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.sink.JavaRuntimeCommandSinkRule;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SinkRule;
import com.totalsecurity.sast.taint.TaintState;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
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

class CommandInjectionDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final CommandInjectionDetector DETECTOR = new CommandInjectionDetector();
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
                    .filter(candidate -> candidate.name().equals("CommandInjectionFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @ParameterizedTest
    @MethodSource("springParameterSources")
    void springParameterSourceReachesRuntimeExec(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, sinkTaint(analysis));
    }

    private static Stream<String> springParameterSources() {
        return Stream.of("requestParam", "pathVariable", "requestBody", "requestHeader", "cookieValue");
    }

    @ParameterizedTest
    @MethodSource("declaredRuntimeReceivers")
    void declaredRuntimeReceiverTypesAreSupported(String methodName) {
        Analysis analysis = analyze(methodName);
        assertEquals(1, analysis.findings().size());
        assertEquals(JavaRuntimeCommandSinkRule.ID, only(analysis.result().sinkMatches()).ruleId());
    }

    private static Stream<String> declaredRuntimeReceivers() {
        return Stream.of("requestParam", "localRuntime", "parameterRuntime");
    }

    @Test
    void servletGetParameterReachesRuntimeExec() {
        Finding finding = only(analyze("servletSource").findings());
        assertEquals("SERVLET_HTTP_REQUEST_VALUE", finding.sources().getFirst().sourceRuleId());
    }

    @Test
    void sourceFlowsThroughLocalAssignment() {
        Finding finding = only(analyze("localAssignment").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().startsWith("Definition of command")));
    }

    @Test
    void directBinaryCommandExpressionIsTainted() {
        Finding finding = only(analyze("binaryCommand").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Binary expression +")));
    }

    @Test
    void stringTrimPreservesTaint() {
        Finding finding = only(analyze("throughTrim").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of trim")));
    }

    @Test
    void oneTaintedBranchProducesMayTaintFinding() {
        assertEquals(1, analyze("branch").findings().size());
    }

    @Test
    void loopCarriedTaintProducesFinding() {
        assertEquals(1, analyze("loop").findings().size());
    }

    @Test
    void stringCommandAndEnvironmentOverloadIsSupported() {
        assertEquals(1, analyze("withEnvironment").findings().size());
    }

    @Test
    void stringCommandEnvironmentAndDirectoryOverloadIsSupported() {
        assertEquals(1, analyze("withEnvironmentAndDirectory").findings().size());
    }

    @Test
    void exactRuntimeFactoryChainIsSupported() {
        Analysis analysis = analyze("chained");
        assertEquals(1, analysis.findings().size());
        assertEquals("java.lang.Runtime", only(analysis.result().sinkMatches())
                .call().call().receiver()
                .map(receiver -> receiver instanceof com.totalsecurity.sast.ir.expression.MethodCallExpression
                        ? "java.lang.Runtime"
                        : "unexpected")
                .orElseThrow());
    }

    @Test
    void fixedCommandIsCleanAndProducesNoFinding() {
        Analysis analysis = analyze("fixedCommand");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void sourceWithoutCommandSinkProducesNoFinding() {
        Analysis analysis = analyze("sourceWithoutSink");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void cleanOverwriteKillsTaintedDefinition() {
        Analysis analysis = analyze("cleanOverwrite");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @ParameterizedTest
    @MethodSource("customExecMethods")
    void customExecDoesNotMatch(String methodName) {
        Analysis analysis = analyze(methodName);
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    private static Stream<String> customExecMethods() {
        return Stream.of("customRuntime", "customExecutor");
    }

    @Test
    void unknownMethodReturnDoesNotProduceConfirmedFinding() {
        Analysis analysis = analyze("unknownReturn");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.UNKNOWN, sinkTaint(analysis));
    }

    @Test
    void stringArrayCommandOverloadIsOutsideScope() {
        Analysis analysis = analyze("unsupportedStringArray");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void ordinaryMethodWithTaintedArgumentIsNotCommandSink() {
        Analysis analysis = analyze("ordinaryMethod");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void processBuilderObjectStateFlowIsNotClaimed() {
        Analysis analysis = analyze("processBuilder");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void findingMetadataAndSinkEvidenceArePreserved() {
        Finding finding = only(analyze("requestParam").findings());
        assertEquals(CommandInjectionDetector.RULE_ID, finding.ruleId());
        assertEquals("OS Command Injection", finding.vulnerabilityType());
        assertEquals("CWE-78", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertEquals(JavaRuntimeCommandSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.COMMAND_EXECUTION, finding.sink().category());
        assertEquals("exec", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertTrue(finding.evidence().contains("Tainted external input reaches supported operating-system"));
        assertFalse(finding.evidence().contains("100%"));
        assertFalse(finding.evidence().contains("shell"));
    }

    @Test
    void sourceEvidenceAndOrderedProvenanceArePreserved() {
        Finding finding = only(analyze("localAssignment").findings());
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

    @Test
    void duplicateCommandRulesAtSamePhysicalArgumentProduceOneFinding() {
        SinkRule duplicate = new SinkRule() {
            @Override
            public String id() {
                return "ZZ_TEST_DUPLICATE_COMMAND";
            }

            @Override
            public Optional<SinkMatch> match(CallSiteContext context) {
                if (!context.receiverQualifiedType().filter("java.lang.Runtime"::equals).isPresent()
                        || !context.methodName().equals("exec")
                        || context.argumentCount() != 1
                        || !context.argumentHasType(0, "java.lang.String")) {
                    return Optional.empty();
                }
                return Optional.of(new SinkMatch(
                        id(), SinkCategory.COMMAND_EXECUTION, context.call(), Set.of(0),
                        context.location(), "synthetic duplicate command rule"));
            }
        };
        List<SinkRule> sinks = new ArrayList<>(RULES.sinkRules());
        sinks.add(duplicate);
        RuleRegistry duplicated = new RuleRegistry(
                RULES.sourceRules(), sinks, RULES.sanitizerRules(), RULES.methodModels());

        Analysis analysis = analyze("requestParam", duplicated);
        assertEquals(2, analysis.result().sinkMatches().size());
        assertEquals(1, analysis.findings().size());
        assertEquals(JavaRuntimeCommandSinkRule.ID, analysis.findings().getFirst().sink().sinkRuleId());
    }

    private static Analysis analyze(String methodName) {
        return analyze(methodName, RULES);
    }

    private static Analysis analyze(String methodName, RuleRegistry rules) {
        MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        RuleAwareTaintResult result =
                new RuleAwareTaintAnalysis().analyze(file, type, method, dataFlow, rules);
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
        var resource = CommandInjectionDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/CommandInjectionFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 9 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
