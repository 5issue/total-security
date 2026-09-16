package com.totalsecurity.sast.detector.sql;

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
import com.totalsecurity.sast.finding.FindingSourceKind;
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
import com.totalsecurity.sast.rule.sink.JdbcConnectionSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcStatementSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcTemplateSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JpaNativeQuerySinkRule;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.sink.SinkRule;
import com.totalsecurity.sast.taint.TaintState;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SqlInjectionDetectorTest {
    private static final RuleRegistry RULES = RuleRegistry.javaSpringBackendDefaults();
    private static final SqlInjectionDetector DETECTOR = new SqlInjectionDetector();
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
                    .filter(candidate -> candidate.name().equals("SqlInjectionFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
        }
    }

    @Test
    void requestParamReachingStatementExecuteQueryProducesFinding() {
        Analysis analysis = analyze("directJdbc");
        Finding finding = only(analysis.findings());
        assertEquals(TaintState.TAINTED, analysis.result().sinkArgumentTaint(only(analysis.result().sinkMatches()), 0).state());
        assertEquals("SPRING_MVC_REQUEST_PARAM", finding.sources().getFirst().sourceRuleId());
    }

    @Test
    void assignmentChainProducesOrderedReproducibleFlow() {
        Finding finding = only(analyze("assignmentChain").findings());
        List<String> summaries = finding.flows().getFirst().steps().stream()
                .map(step -> step.summary())
                .toList();

        assertEquals(FindingFlowStepKind.SOURCE, finding.flows().getFirst().steps().getFirst().kind());
        assertEquals(FindingFlowStepKind.SINK, finding.flows().getFirst().steps().getLast().kind());
        assertTrue(summaries.stream().anyMatch(summary -> summary.startsWith("Definition of sql")));
        assertTrue(summaries.stream().anyMatch(summary -> summary.startsWith("Definition of query")));
        assertTrue(summaries.stream().anyMatch(summary -> summary.equals("Use of query")));
    }

    @Test
    void stringTrimPropagationProducesFinding() {
        Finding finding = only(analyze("throughTrim").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("Return value of trim")));
    }

    @Test
    void directBinarySinkArgumentProducesFinding() {
        assertEquals(1, analyze("directBinary").findings().size());
    }

    @Test
    void taintedBranchMayReachSink() {
        Analysis analysis = analyze("branch");
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, sinkTaint(analysis));
    }

    @Test
    void taintedLoopMayReachSink() {
        Analysis analysis = analyze("loop");
        assertEquals(1, analysis.findings().size());
        assertEquals(TaintState.TAINTED, sinkTaint(analysis));
    }

    @Test
    void connectionPrepareStatementTaintedSqlProducesFinding() {
        Finding finding = only(analyze("connection").findings());
        assertEquals(JdbcConnectionSqlSinkRule.ID, finding.sink().sinkRuleId());
    }

    @Test
    void jdbcTemplateTaintedSqlProducesFinding() {
        Finding finding = only(analyze("jdbcTemplatePositive").findings());
        assertEquals(JdbcTemplateSqlSinkRule.ID, finding.sink().sinkRuleId());
    }

    @Test
    void entityManagerTaintedNativeSqlProducesFinding() {
        Finding finding = only(analyze("jpaPositive").findings());
        assertEquals(JpaNativeQuerySinkRule.ID, finding.sink().sinkRuleId());
    }

    @Test
    void servletGetterSourceReachesSqlSink() {
        Finding finding = only(analyze("servletSource").findings());
        assertEquals("SERVLET_HTTP_REQUEST_VALUE", finding.sources().getFirst().sourceRuleId());
        assertEquals(FindingSourceKind.EXPRESSION, finding.sources().getFirst().kind());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.summary().equals("External return value of getParameter")));
    }

    @Test
    void preparedStatementBindingWithLiteralSqlProducesNoFinding() {
        Analysis analysis = analyze("preparedBindingSafe");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(1, analysis.result().sinkMatches().size());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void jpaNamedParameterBindingWithLiteralSqlProducesNoFinding() {
        Analysis analysis = analyze("jpaBindingSafe");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(1, analysis.result().sinkMatches().size());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void jdbcTemplatePlaceholderDataIsNotSqlTextFinding() {
        Analysis analysis = analyze("jdbcTemplateBindingSafe");
        SinkMatch sink = only(analysis.result().sinkMatches());
        assertTrue(analysis.findings().isEmpty());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
        assertEquals(TaintState.CLEAN, analysis.result().sinkArgumentTaint(sink, 0).state());
        assertEquals(TaintState.TAINTED, analysis.result().taintResult().argumentTaint(sink.call(), 1).state());
    }

    @Test
    void cleanOverwritePreventsFinding() {
        Analysis analysis = analyze("overwritten");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void sqlSinkWithoutExternalSourceProducesNoFinding() {
        Analysis analysis = analyze("sinkWithoutSource");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void externalSourceWithoutSqlSinkProducesNoFinding() {
        Analysis analysis = analyze("sourceWithoutSink");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(1, analysis.result().sourceMatches().size());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void customExecuteQueryIsNotSqlSink() {
        Analysis analysis = analyze("customExecuteQuery");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sinkMatches().isEmpty());
    }

    @Test
    void customRequestParamIsNotExternalSource() {
        Analysis analysis = analyze("customRequestParam");
        assertTrue(analysis.findings().isEmpty());
        assertTrue(analysis.result().sourceMatches().isEmpty());
        assertEquals(TaintState.CLEAN, sinkTaint(analysis));
    }

    @Test
    void unknownMethodReturnDoesNotProduceConfirmedFinding() {
        Analysis analysis = analyze("unknownReturn");
        assertTrue(analysis.findings().isEmpty());
        assertEquals(TaintState.UNKNOWN, sinkTaint(analysis));
    }

    @Test
    void multipleSourcesAtOnePhysicalSinkProduceOneFinding() {
        Analysis analysis = analyze("multipleSources");
        assertEquals(1, analysis.findings().size());
        assertEquals(1, analysis.result().sinkMatches().size());
    }

    @Test
    void duplicateSqlSinkRulesAtSamePhysicalArgumentProduceOneFinding() {
        SinkRule duplicate = new SinkRule() {
            @Override
            public String id() {
                return "ZZ_TEST_DUPLICATE_SQL_TEXT";
            }

            @Override
            public Optional<SinkMatch> match(CallSiteContext context) {
                if (!context.methodName().equals("executeQuery")
                        || context.argumentCount() != 1
                        || !context.argumentHasType(0, "java.lang.String")) {
                    return Optional.empty();
                }
                return Optional.of(new SinkMatch(
                        id(),
                        SinkCategory.SQL_TEXT,
                        context.call(),
                        Set.of(0),
                        context.location(),
                        "synthetic duplicate SQL-text rule"));
            }
        };
        List<SinkRule> sinks = new java.util.ArrayList<>(RULES.sinkRules());
        sinks.add(duplicate);
        RuleRegistry duplicated = new RuleRegistry(
                RULES.sourceRules(), sinks, RULES.sanitizerRules(), RULES.methodModels());

        Analysis analysis = analyze("directJdbc", duplicated);
        assertEquals(2, analysis.result().sinkMatches().size());
        assertEquals(1, analysis.findings().size());
        assertEquals(JdbcStatementSqlSinkRule.ID, analysis.findings().getFirst().sink().sinkRuleId());
    }

    @Test
    void multipleSourceOriginsAreAllPreserved() {
        Finding finding = only(analyze("multipleSources").findings());
        assertEquals(
                Set.of("SPRING_MVC_REQUEST_PARAM", "SPRING_MVC_REQUEST_HEADER"),
                finding.sources().stream().map(source -> source.sourceRuleId()).collect(Collectors.toSet()));
        assertEquals(2, finding.sources().size());
        assertEquals(2, finding.flows().size());
    }

    @Test
    void directBinaryArgumentHasExpressionProvenanceFlow() {
        Finding finding = only(analyze("directBinary").findings());
        assertTrue(finding.flows().getFirst().steps().stream()
                .anyMatch(step -> step.kind() == FindingFlowStepKind.EXPRESSION
                        && step.summary().equals("Binary expression +")));
        assertTrue(finding.flows().getFirst().steps().stream()
                .allMatch(step -> step.location() != null));
    }

    @Test
    void sinkEvidenceKeepsEnvironmentRuleMethodAndArgument() {
        Finding finding = only(analyze("directJdbc").findings());
        assertEquals(JdbcStatementSqlSinkRule.ID, finding.sink().sinkRuleId());
        assertEquals(SinkCategory.SQL_TEXT, finding.sink().category());
        assertEquals("executeQuery", finding.sink().methodName());
        assertEquals(0, finding.sink().argumentIndex());
        assertEquals(finding.sink().location().file(), finding.primaryLocation().file());
    }

    @Test
    void findingMetadataIsSqlInjectionCwe89High() {
        Finding finding = only(analyze("directJdbc").findings());
        assertEquals(SqlInjectionDetector.RULE_ID, finding.ruleId());
        assertEquals("SQL Injection", finding.vulnerabilityType());
        assertEquals("CWE-89", finding.cwe());
        assertEquals(FindingSeverity.HIGH, finding.severity());
        assertTrue(finding.evidence().contains("Tainted external input reaches SQL text argument 0"));
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
        var resource = SqlInjectionDetectorTest.class
                .getClassLoader()
                .getResource("fixtures/SqlInjectionFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 7 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(RuleAwareTaintResult result, List<Finding> findings) {}
}
