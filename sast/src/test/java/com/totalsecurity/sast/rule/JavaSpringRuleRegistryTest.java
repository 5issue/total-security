package com.totalsecurity.sast.rule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.DefinitionKind;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.sanitizer.SanitizerRule;
import com.totalsecurity.sast.rule.sink.JdbcConnectionSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcStatementSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JdbcTemplateSqlSinkRule;
import com.totalsecurity.sast.rule.sink.JpaNativeQuerySinkRule;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.ServletRequestSourceRule;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.DefinitionTaintSeed;
import com.totalsecurity.sast.taint.ExpressionTaintSeed;
import com.totalsecurity.sast.taint.IntraproceduralTaintAnalysis;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintState;
import com.totalsecurity.sast.taint.model.AmbiguousMethodTaintModelException;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;
import com.totalsecurity.sast.taint.model.MethodTaintModelRegistry;
import com.totalsecurity.sast.taint.model.MethodTaintSemantics;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class JavaSpringRuleRegistryTest {
    private static final RuleRegistry DEFAULTS = RuleRegistry.javaSpringBackendDefaults();
    private static Fixture rules;
    private static Fixture custom;

    @BeforeAll
    static void loadFixtures() throws Exception {
        rules = load("Step6RulesFixture.java", "Step6RulesFixture");
        custom = load("Step6CustomFixture.java", "Step6CustomFixture");
    }

    @Test
    void matchesSpringRequestParamParameter() {
        assertSingleParameterSource("requestParam", "SPRING_MVC_REQUEST_PARAM");
    }

    @Test
    void matchesSpringPathVariableParameter() {
        assertSingleParameterSource("pathVariable", "SPRING_MVC_PATH_VARIABLE");
    }

    @Test
    void matchesSpringRequestBodyParameter() {
        assertSingleParameterSource("requestBody", "SPRING_MVC_REQUEST_BODY");
    }

    @Test
    void matchesSpringRequestHeaderParameter() {
        assertSingleParameterSource("requestHeader", "SPRING_MVC_REQUEST_HEADER");
    }

    @Test
    void matchesSpringCookieValueParameter() {
        assertSingleParameterSource("cookieValue", "SPRING_MVC_COOKIE_VALUE");
    }

    @Test
    void doesNotMatchCustomAnnotationWithSameSimpleName() {
        Prepared prepared = custom.prepare("customAnnotation");
        assertTrue(matchesSources(DEFAULTS, prepared).isEmpty());
    }

    @Test
    void matchesServletRequestGetterReturnAndCreatesExpressionSeed() {
        Prepared prepared = rules.prepare("servletParameter");
        SourceMatch match = only(matchesSources(DEFAULTS, prepared));

        assertEquals(ServletRequestSourceRule.ID, match.ruleId());
        assertInstanceOf(ExpressionSourceMatch.class, match);
        assertInstanceOf(ExpressionTaintSeed.class, match.toTaintSeed(prepared.dataFlow()));
    }

    @Test
    void doesNotMatchCustomGetParameterMethod() {
        Prepared prepared = custom.prepare("customCalls");
        assertTrue(matchesSources(DEFAULTS, prepared).isEmpty());
    }

    @Test
    void matchesJdbcStatementExecuteQuerySqlArgument() {
        Prepared prepared = rules.prepare("jdbcStatement");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        CallSiteContext context = context(prepared, "executeQuery");

        assertEquals(JdbcStatementSqlSinkRule.ID, match.ruleId());
        assertEquals(Set.of(0), match.sensitiveArgumentIndexes());
        assertEquals(Optional.of("Statement"), context.receiverDeclaredType());
        assertEquals(Optional.of("java.sql.Statement"), context.receiverQualifiedType());
    }

    @Test
    void doesNotMatchCustomExecuteQueryMethod() {
        Prepared prepared = custom.prepare("customCalls");
        assertTrue(matchesSinks(DEFAULTS, prepared).isEmpty());
    }

    @Test
    void matchesConnectionPrepareStatementSqlArgument() {
        Prepared prepared = rules.prepare("jdbcConnection");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        assertEquals(JdbcConnectionSqlSinkRule.ID, match.ruleId());
        assertEquals(Set.of(0), match.sensitiveArgumentIndexes());
    }

    @Test
    void preparedStatementSetStringIsNotSqlTextSink() {
        Prepared prepared = rules.prepare("preparedBinding");
        assertTrue(matchesSinks(DEFAULTS, prepared).isEmpty());
    }

    @Test
    void matchesJdbcTemplateSqlArgument() {
        Prepared prepared = rules.prepare("springJdbc");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        assertEquals(JdbcTemplateSqlSinkRule.ID, match.ruleId());
        assertEquals(Set.of(0), match.sensitiveArgumentIndexes());
    }

    @Test
    void jdbcTemplatePlaceholderDataIsNotMarkedAsSqlText() {
        Prepared prepared = rules.prepare("springJdbc");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        assertEquals(2, match.call().call().arguments().size());
        assertTrue(!match.sensitiveArgumentIndexes().contains(1));
    }

    @Test
    void matchesEntityManagerNativeQuerySqlArgument() {
        Prepared prepared = rules.prepare("jpaNative");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        assertEquals(JpaNativeQuerySinkRule.ID, match.ruleId());
        assertEquals(Set.of(0), match.sensitiveArgumentIndexes());
    }

    @Test
    void querySetParameterIsNotSqlTextSink() {
        Prepared prepared = rules.prepare("jpaBinding");
        assertTrue(matchesSinks(DEFAULTS, prepared).isEmpty());
    }

    @Test
    void unmodeledMethodReturnRemainsUnknown() {
        Prepared prepared = rules.prepare("unmodeled");
        TaintAnalysisResult result = analyze(DEFAULTS, prepared, "input");
        assertEquals(TaintState.UNKNOWN, result.taintOf(local(prepared, "value")).state());
    }

    @Test
    void stringTrimPropagatesTaintedReceiverToReturn() {
        Prepared prepared = rules.prepare("trimTainted");
        TaintAnalysisResult result = analyze(DEFAULTS, prepared, "input");
        MethodCallExpression trim = call(prepared, "trim");

        assertEquals(TaintState.TAINTED, result.receiverTaint(trim).orElseThrow().state());
        assertEquals(TaintState.TAINTED, result.methodCallTaint(trim).orElseThrow().result().state());
        assertEquals(TaintState.TAINTED, result.taintOf(local(prepared, "value")).state());
    }

    @Test
    void stringTrimKeepsCleanReceiverClean() {
        Prepared prepared = rules.prepare("trimClean");
        TaintAnalysisResult result = analyze(DEFAULTS, prepared);
        MethodCallExpression trim = call(prepared, "trim");
        assertEquals(TaintState.CLEAN, result.methodCallTaint(trim).orElseThrow().result().state());
    }

    @Test
    void selectedArgumentModelPropagatesOnlyConfiguredArgument() {
        MethodTaintModel selected = model(
                "TEST_SELECTED_ARGUMENT",
                "choose",
                MethodTaintSemantics.propagateSelectedArguments(Set.of(1)));
        RuleRegistry registry = registryWithModels(List.of(selected));
        Prepared prepared = rules.prepare("selectedArguments");

        assertEquals(TaintState.CLEAN, analyze(registry, prepared, "left").taintOf(local(prepared, "value")).state());
        assertEquals(TaintState.TAINTED, analyze(registry, prepared, "right").taintOf(local(prepared, "value")).state());
    }

    @Test
    void syntheticSanitizerProducesCleanReturn() {
        SanitizerRule sanitizer = new SanitizerRule() {
            @Override
            public String id() {
                return "TEST_VERIFIED_CLEAN";
            }

            @Override
            public Optional<MethodTaintSemantics> match(CallSiteContext context) {
                return context.methodName().equals("verifiedClean")
                        ? Optional.of(MethodTaintSemantics.sanitizedReturn())
                        : Optional.empty();
            }
        };
        RuleRegistry registry = new RuleRegistry(List.of(), List.of(), List.of(sanitizer), List.of());
        Prepared prepared = rules.prepare("sanitized");

        TaintAnalysisResult result = analyze(registry, prepared, "input");
        assertEquals(TaintState.TAINTED, result.argumentTaint(call(prepared, "verifiedClean"), 0).state());
        assertEquals(TaintState.CLEAN, result.taintOf(local(prepared, "value")).state());
    }

    @Test
    void ordinaryTrimAndReplaceArePropagationNotSecuritySanitizers() {
        Prepared prepared = rules.prepare("ordinaryStringMethods");
        TaintAnalysisResult result = analyze(DEFAULTS, prepared, "input");

        assertTrue(DEFAULTS.sanitizerRules().isEmpty());
        assertEquals(TaintState.TAINTED, result.taintOf(local(prepared, "trimmed")).state());
        assertEquals(TaintState.TAINTED, result.taintOf(local(prepared, "replaced")).state());
    }

    @Test
    void parameterSourceMatchConvertsToDefinitionSeed() {
        Prepared prepared = rules.prepare("requestParam");
        SourceMatch match = only(matchesSources(DEFAULTS, prepared));
        TaintSeed seed = match.toTaintSeed(prepared.dataFlow());

        DefinitionTaintSeed definitionSeed = assertInstanceOf(DefinitionTaintSeed.class, seed);
        assertEquals(parameter(prepared, "input"), definitionSeed.definition());
    }

    @Test
    void sinkMatchExposesExactArgumentIndexForStepSeven() {
        Prepared prepared = rules.prepare("endToEnd");
        SinkMatch match = only(matchesSinks(DEFAULTS, prepared));
        assertEquals(JdbcStatementSqlSinkRule.ID, match.ruleId());
        assertEquals(Set.of(0), match.sensitiveArgumentIndexes());
        assertEquals(match.call().location(), match.location());
    }

    @Test
    void sourceSeedFlowsToMatchedSinkArgumentWithoutCreatingFinding() {
        Prepared prepared = rules.prepare("endToEnd");
        List<TaintSeed> seeds = DEFAULTS.sourceSeeds(
                prepared.fixture().file(), prepared.fixture().type(), prepared.method(), prepared.dataFlow());
        SinkMatch sink = only(matchesSinks(DEFAULTS, prepared));
        TaintAnalysisResult result = new IntraproceduralTaintAnalysis().analyze(
                prepared.dataFlow(),
                seeds,
                DEFAULTS.methodSemantics(
                        prepared.fixture().file(), prepared.fixture().type(), prepared.method(), prepared.dataFlow()));

        assertEquals(1, seeds.size());
        assertEquals(TaintState.TAINTED, result.argumentTaint(sink.call(), 0).state());
    }

    @Test
    void sanitizerPriorityBeatsMatchingGenericPropagation() {
        Prepared prepared = rules.prepare("sanitized");
        MethodTaintModel generic = model(
                "TEST_GENERIC",
                "verifiedClean",
                MethodTaintModelPriority.GENERIC_PROPAGATION,
                MethodTaintSemantics.propagateArguments());
        SanitizerRule sanitizer = sanitizer("TEST_SANITIZER", "verifiedClean");
        MethodTaintModelRegistry models =
                new MethodTaintModelRegistry(prepared.contexts(), List.of(generic, sanitizer));

        TaintAnalysisResult result = new IntraproceduralTaintAnalysis().analyze(
                prepared.dataFlow(),
                List.of(new DefinitionTaintSeed("test:input", parameter(prepared, "input"))),
                models);
        assertEquals(TaintState.CLEAN, result.taintOf(local(prepared, "value")).state());
    }

    @Test
    void prioritySelectionDoesNotDependOnRegistrationOrder() {
        Prepared prepared = rules.prepare("sanitized");
        MethodCallExpression call = call(prepared, "verifiedClean");
        MethodTaintModel generic = model(
                "TEST_GENERIC",
                "verifiedClean",
                MethodTaintModelPriority.GENERIC_PROPAGATION,
                MethodTaintSemantics.propagateArguments());
        SanitizerRule sanitizer = sanitizer("TEST_SANITIZER", "verifiedClean");

        MethodTaintSemantics genericFirst = new MethodTaintModelRegistry(
                        prepared.contexts(), List.of(generic, sanitizer))
                .semanticsFor(call)
                .orElseThrow();
        MethodTaintSemantics sanitizerFirst = new MethodTaintModelRegistry(
                        prepared.contexts(), List.of(sanitizer, generic))
                .semanticsFor(call)
                .orElseThrow();
        assertEquals(MethodTaintSemantics.sanitizedReturn(), genericFirst);
        assertEquals(genericFirst, sanitizerFirst);
    }

    @Test
    void equivalentModelsAtSamePriorityAreOrderIndependent() {
        Prepared prepared = rules.prepare("selectedArguments");
        MethodCallExpression call = call(prepared, "choose");
        MethodTaintSemantics semantics = MethodTaintSemantics.propagateSelectedArguments(Set.of(1));
        MethodTaintModel first = model(
                "MODEL_A",
                "choose",
                MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION,
                semantics);
        MethodTaintModel second = model(
                "MODEL_B",
                "choose",
                MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION,
                semantics);

        assertEquals(
                semantics,
                new MethodTaintModelRegistry(prepared.contexts(), List.of(first, second))
                        .semanticsFor(call)
                        .orElseThrow());
        assertEquals(
                semantics,
                new MethodTaintModelRegistry(prepared.contexts(), List.of(second, first))
                        .semanticsFor(call)
                        .orElseThrow());
    }

    @Test
    void conflictingModelsAtSameHighestPriorityAreExplicitlyRejected() {
        Prepared prepared = rules.prepare("sanitized");
        MethodTaintModel clean = model(
                "MODEL_A",
                "verifiedClean",
                MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION,
                MethodTaintSemantics.sanitizedReturn());
        MethodTaintModel propagate = model(
                "MODEL_B",
                "verifiedClean",
                MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION,
                MethodTaintSemantics.propagateArguments());
        MethodTaintModelRegistry models =
                new MethodTaintModelRegistry(prepared.contexts(), List.of(propagate, clean));

        AmbiguousMethodTaintModelException error = assertThrows(
                AmbiguousMethodTaintModelException.class,
                () -> models.semanticsFor(call(prepared, "verifiedClean")));
        assertEquals(MethodTaintModelPriority.FRAMEWORK_SPECIFIC_PROPAGATION, error.priority());
        assertEquals(List.of("MODEL_A", "MODEL_B"), error.modelIds());
    }

    @Test
    void ruleAwareAnalysisAutomaticallyCreatesSpringParameterSeed() {
        RuleAwareTaintResult result = ruleAware(rules.prepare("ruleAwareFlow"));

        assertEquals(1, result.sourceMatches().size());
        assertEquals("SPRING_MVC_REQUEST_PARAM", result.sourceMatches().getFirst().ruleId());
        assertEquals(1, result.taintSeeds().size());
        assertInstanceOf(DefinitionTaintSeed.class, result.taintSeeds().getFirst());
    }

    @Test
    void ruleAwareAnalysisInjectsDefaultMethodSemantics() {
        Prepared prepared = rules.prepare("ruleAwareFlow");
        RuleAwareTaintResult result = ruleAware(prepared);
        MethodCallExpression trim = call(prepared, "trim");

        assertEquals(
                TaintState.TAINTED,
                result.taintResult().methodCallTaint(trim).orElseThrow().result().state());
        assertEquals(TaintState.TAINTED, result.taintResult().taintOf(local(prepared, "value")).state());
    }

    @Test
    void ruleAwareSourceThroughStringMethodReachesSinkArgument() {
        Prepared prepared = rules.prepare("ruleAwareFlow");
        RuleAwareTaintResult result = ruleAware(prepared);
        SinkMatch sink = only(result.sinkMatches());

        assertEquals(JdbcStatementSqlSinkRule.ID, sink.ruleId());
        assertEquals(TaintState.TAINTED, result.sinkArgumentTaint(sink, 0).state());
    }

    @Test
    void ruleAwareResultExposesStepSevenReadySinkMatch() {
        Prepared prepared = rules.prepare("ruleAwareFlow");
        RuleAwareTaintResult result = ruleAware(prepared);
        SinkMatch sink = only(result.sinkMatches());

        assertEquals("executeQuery", sink.call().call().methodName());
        assertEquals(Set.of(0), sink.sensitiveArgumentIndexes());
        assertEquals(sink.call().location(), sink.location());
    }

    private static void assertSingleParameterSource(String methodName, String ruleId) {
        Prepared prepared = rules.prepare(methodName);
        SourceMatch match = only(matchesSources(DEFAULTS, prepared));
        assertEquals(ruleId, match.ruleId());
        assertInstanceOf(ParameterSourceMatch.class, match);
    }

    private static List<SourceMatch> matchesSources(RuleRegistry registry, Prepared prepared) {
        return registry.matchSources(
                prepared.fixture().file(), prepared.fixture().type(), prepared.method(), prepared.dataFlow());
    }

    private static List<SinkMatch> matchesSinks(RuleRegistry registry, Prepared prepared) {
        return registry.matchSinks(
                prepared.fixture().file(), prepared.fixture().type(), prepared.method(), prepared.dataFlow());
    }

    private static TaintAnalysisResult analyze(
            RuleRegistry registry, Prepared prepared, String... seededParameters) {
        List<TaintSeed> seeds = Arrays.stream(seededParameters)
                .map(name -> new DefinitionTaintSeed("test:" + name, parameter(prepared, name)))
                .map(TaintSeed.class::cast)
                .toList();
        return new IntraproceduralTaintAnalysis().analyze(
                prepared.dataFlow(),
                seeds,
                registry.methodSemantics(
                        prepared.fixture().file(), prepared.fixture().type(), prepared.method(), prepared.dataFlow()));
    }

    private static RuleRegistry registryWithModels(List<? extends MethodTaintModel> models) {
        return new RuleRegistry(List.of(), List.of(), List.of(), models);
    }

    private static MethodTaintModel model(
            String id, String methodName, MethodTaintSemantics semantics) {
        return model(
                id,
                methodName,
                MethodTaintModelPriority.GENERIC_PROPAGATION,
                semantics);
    }

    private static MethodTaintModel model(
            String id,
            String methodName,
            MethodTaintModelPriority priority,
            MethodTaintSemantics semantics) {
        return new MethodTaintModel() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public MethodTaintModelPriority priority() {
                return priority;
            }

            @Override
            public Optional<MethodTaintSemantics> match(CallSiteContext context) {
                return context.methodName().equals(methodName)
                        ? Optional.of(semantics)
                        : Optional.empty();
            }
        };
    }

    private static SanitizerRule sanitizer(String id, String methodName) {
        return new SanitizerRule() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public Optional<MethodTaintSemantics> match(CallSiteContext context) {
                return context.methodName().equals(methodName)
                        ? Optional.of(MethodTaintSemantics.sanitizedReturn())
                        : Optional.empty();
            }
        };
    }

    private static RuleAwareTaintResult ruleAware(Prepared prepared) {
        return new RuleAwareTaintAnalysis().analyze(
                prepared.fixture().file(),
                prepared.fixture().type(),
                prepared.method(),
                prepared.dataFlow(),
                DEFAULTS);
    }

    private static CallSiteContext context(Prepared prepared, String methodName) {
        return prepared.contexts().callSites().stream()
                .filter(candidate -> candidate.methodName().equals(methodName))
                .findFirst()
                .orElseThrow();
    }

    private static MethodCallExpression call(Prepared prepared, String methodName) {
        return context(prepared, methodName).call();
    }

    private static Definition parameter(Prepared prepared, String name) {
        return definition(prepared, name, DefinitionKind.PARAMETER);
    }

    private static Definition local(Prepared prepared, String name) {
        return prepared.dataFlow().definitions().stream()
                .filter(definition -> definition.kind() != DefinitionKind.PARAMETER)
                .filter(definition -> definition.variable().name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static Definition definition(Prepared prepared, String name, DefinitionKind kind) {
        return prepared.dataFlow().definitions().stream()
                .filter(definition -> definition.kind() == kind)
                .filter(definition -> definition.variable().name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static <T> T only(List<T> values) {
        assertEquals(1, values.size());
        return values.getFirst();
    }

    private static Fixture load(String resourceName, String className) throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsed = parser.parse(fixturePath(resourceName))) {
            assertTrue(!parsed.hasSyntaxErrors());
            JavaFileInfo file = new JavaSemanticExtractor().extract(parsed);
            ClassInfo type = file.types().stream()
                    .filter(candidate -> candidate.name().equals(className))
                    .findFirst()
                    .orElseThrow();
            Map<String, MethodInfo> methods = type.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, Function.identity()));
            return new Fixture(file, type, methods);
        }
    }

    private static Path fixturePath(String name) throws URISyntaxException {
        var resource = JavaSpringRuleRegistryTest.class
                .getClassLoader()
                .getResource("fixtures/" + name);
        if (resource == null) {
            throw new IllegalStateException("STEP 6 fixture not found: " + name);
        }
        return Path.of(resource.toURI());
    }

    private record Fixture(JavaFileInfo file, ClassInfo type, Map<String, MethodInfo> methods) {
        private Prepared prepare(String methodName) {
            MethodInfo method = Optional.ofNullable(methods.get(methodName)).orElseThrow();
            ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
            DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
            return new Prepared(
                    this,
                    method,
                    dataFlow,
                    new CallSiteContextResolver(file, type, method, dataFlow));
        }
    }

    private record Prepared(
            Fixture fixture,
            MethodInfo method,
            DataFlowResult dataFlow,
            CallSiteContextResolver contexts) {}
}
