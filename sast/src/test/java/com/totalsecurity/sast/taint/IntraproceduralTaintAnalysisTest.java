package com.totalsecurity.sast.taint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.DefinitionKind;
import com.totalsecurity.sast.dataflow.ReachingDefinitionsAnalysis;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.dataflow.VariableSymbol;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class IntraproceduralTaintAnalysisTest {
    private static Map<String, MethodInfo> methods;

    @BeforeAll
    static void extractFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixturePath())) {
            assertFalse(parsedFile.hasSyntaxErrors());
            JavaFileInfo file = new JavaSemanticExtractor().extract(parsedFile);
            ClassInfo fixture = file.types().stream()
                    .filter(type -> type.name().equals("TaintFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = fixture.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, method -> method));
        }
    }

    @Test
    void implementsRequiredMayTaintLattice() {
        assertEquals(TaintState.CLEAN, TaintState.CLEAN.join(TaintState.CLEAN));
        assertEquals(TaintState.UNKNOWN, TaintState.CLEAN.join(TaintState.UNKNOWN));
        assertEquals(TaintState.UNKNOWN, TaintState.UNKNOWN.join(TaintState.UNKNOWN));
        assertEquals(TaintState.TAINTED, TaintState.TAINTED.join(TaintState.CLEAN));
        assertEquals(TaintState.TAINTED, TaintState.TAINTED.join(TaintState.UNKNOWN));
        assertEquals(TaintState.TAINTED, TaintState.TAINTED.join(TaintState.TAINTED));
    }

    @Test
    void parameterSeedIsTaintedAndUnseededParameterIsClean() {
        Analysis seeded = analyze("unseeded", "input");
        Definition input = parameter(seeded.dataFlow(), "input");
        UseSite seededUse = useInCall(seeded.dataFlow(), "consume", "input");
        assertState(seeded.result().taintOf(input), TaintState.TAINTED, 1);
        assertState(seeded.result().taintOf(seededUse), TaintState.TAINTED, 1);

        Analysis unseeded = analyze("unseeded");
        assertState(
                unseeded.result().taintOf(parameter(unseeded.dataFlow(), "input")),
                TaintState.CLEAN,
                0);
        assertState(
                unseeded.result().taintOf(useInCall(unseeded.dataFlow(), "consume", "input")),
                TaintState.CLEAN,
                0);
    }

    @Test
    void propagatesDirectAssignmentChain() {
        Analysis analysis = analyze("chain", "input");
        for (String variable : List.of("input", "a", "b", "c")) {
            assertEquals(
                    TaintState.TAINTED,
                    analysis.result().taintOf(definition(analysis.dataFlow(), variable)).state());
        }
        UseSite finalUse = useInCall(analysis.dataFlow(), "consume", "c");
        assertEquals(TaintState.TAINTED, analysis.result().taintOf(finalUse).state());
    }

    @Test
    void literalOverwriteKillsTaintWithoutSanitizerSemantics() {
        Analysis analysis = analyze("overwrite", "input");
        List<Definition> values = definitions(analysis.dataFlow(), "value");
        Definition initializer = values.stream()
                .filter(definition -> definition.kind() == DefinitionKind.VARIABLE_INITIALIZER)
                .findFirst()
                .orElseThrow();
        Definition overwrite = values.stream()
                .filter(definition -> definition.kind() == DefinitionKind.ASSIGNMENT)
                .findFirst()
                .orElseThrow();

        assertEquals(TaintState.TAINTED, analysis.result().taintOf(initializer).state());
        assertEquals(TaintState.CLEAN, analysis.result().taintOf(overwrite).state());
        assertEquals(
                TaintState.CLEAN,
                analysis.result().taintOf(useInCall(analysis.dataFlow(), "consume", "value")).state());
    }

    @Test
    void binaryExpressionJoinsOperands() {
        Analysis tainted = analyze("binaryTainted", "input");
        Definition taintedValue = definition(tainted.dataFlow(), "value");
        assertTrue(taintedValue.assignedExpression().orElseThrow() instanceof BinaryExpression);
        assertEquals(TaintState.TAINTED, tainted.result().taintOf(taintedValue).state());

        Analysis clean = analyze("binaryClean");
        Definition cleanValue = definition(clean.dataFlow(), "value");
        assertTrue(cleanValue.assignedExpression().orElseThrow() instanceof BinaryExpression);
        assertEquals(TaintState.CLEAN, clean.result().taintOf(cleanValue).state());
        assertEquals(
                TaintState.CLEAN,
                clean.result().taintOf(useInCall(clean.dataFlow(), "consume", "value")).state());
    }

    @Test
    void branchMergeUsesMayTaintJoin() {
        Analysis analysis = analyze("branchMerge", "input");
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");
        Set<Definition> reaching = analysis.dataFlow().reachingDefinitions(use.reference());

        assertEquals(2, reaching.size());
        assertTrue(reaching.stream()
                .anyMatch(definition -> analysis.result().taintOf(definition).state() == TaintState.TAINTED));
        assertTrue(reaching.stream()
                .anyMatch(definition -> analysis.result().taintOf(definition).state() == TaintState.CLEAN));
        assertEquals(TaintState.TAINTED, analysis.result().taintOf(use).state());
    }

    @Test
    void ifWithoutElseMergesCleanAndTaintedDefinitions() {
        Analysis analysis = analyze("ifWithoutElse", "input");
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");
        assertEquals(2, analysis.dataFlow().reachingDefinitions(use.reference()).size());
        assertEquals(TaintState.TAINTED, analysis.result().taintOf(use).state());
    }

    @Test
    void whileLoopConvergesAndPreservesFiniteStaticTrace() {
        Analysis analysis = analyze("whileFlow", "input");
        Definition loopAssignment = definitions(analysis.dataFlow(), "value").stream()
                .filter(definition -> definition.kind() == DefinitionKind.ASSIGNMENT)
                .findFirst()
                .orElseThrow();
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");

        assertEquals(2, analysis.dataFlow().reachingDefinitions(use.reference()).size());
        assertEquals(TaintState.TAINTED, analysis.result().taintOf(use).state());
        assertTrue(analysis.result().evaluationCount(loopAssignment) > 1);
        assertEquals(
                analysis.result().traceSteps().stream()
                        .map(TaintTraceStep::id)
                        .collect(Collectors.toSet())
                        .size(),
                analysis.result().traceSteps().size());
    }

    @Test
    void forLoopConvergesWithInitializerAndUpdateDataFlow() {
        Analysis analysis = analyze("forFlow", "input");
        Definition loopAssignment = definitions(analysis.dataFlow(), "value").stream()
                .filter(definition -> definition.kind() == DefinitionKind.ASSIGNMENT)
                .findFirst()
                .orElseThrow();
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");

        assertEquals(2, analysis.dataFlow().reachingDefinitions(use.reference()).size());
        assertEquals(TaintState.TAINTED, analysis.result().taintOf(use).state());
        assertTrue(analysis.result().evaluationCount(loopAssignment) > 1);
    }

    @Test
    void exposesMethodReceiverAndArgumentTaintWithoutSinkSemantics() {
        Analysis analysis = analyze("callParts", "receiver", "input");
        MethodCallExpression call = methodCall(analysis.dataFlow(), "execute");
        MethodCallTaint callTaint = analysis.result().methodCallTaint(call).orElseThrow();

        assertEquals(TaintState.TAINTED, callTaint.receiver().orElseThrow().state());
        assertEquals(TaintState.TAINTED, analysis.result().argumentTaint(call, 0).state());
        assertEquals(TaintState.CLEAN, analysis.result().argumentTaint(call, 1).state());
        assertEquals(TaintState.UNKNOWN, callTaint.result().state());
    }

    @Test
    void arbitraryMethodReturnIsUnknownEvenWhenArgumentIsTainted() {
        Analysis analysis = analyze("arbitraryReturn", "input");
        MethodCallExpression transform = methodCall(analysis.dataFlow(), "transform");
        Definition value = definition(analysis.dataFlow(), "value");

        assertEquals(TaintState.TAINTED, analysis.result().argumentTaint(transform, 0).state());
        assertEquals(TaintState.UNKNOWN, analysis.result().methodCallTaint(transform).orElseThrow().result().state());
        assertEquals(TaintState.UNKNOWN, analysis.result().taintOf(value).state());
        assertEquals(
                TaintState.UNKNOWN,
                analysis.result().taintOf(useInCall(analysis.dataFlow(), "consume", "value")).state());
    }

    @Test
    void earlyReturnPathDoesNotContaminateContinuingCleanUse() {
        Analysis analysis = analyze("earlyReturn", "input");
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");
        assertEquals(1, analysis.dataFlow().reachingDefinitions(use.reference()).size());
        assertEquals(TaintState.CLEAN, analysis.result().taintOf(use).state());
    }

    @Test
    void excludesUnreachableDefinitionsExpressionsAndCalls() {
        Analysis analysis = analyze("unreachable", "input");
        BasicBlock unreachable = blockCalling(analysis.dataFlow().graph(), "consume");
        MethodCallExpression call = methodCallInBlock(unreachable, "consume");

        assertFalse(analysis.dataFlow().graph().reachableBlocks().contains(unreachable));
        assertTrue(analysis.dataFlow().definitions().stream()
                .noneMatch(definition -> definition.variable().name().equals("value")));
        assertTrue(analysis.result().methodCalls().stream().noneMatch(item -> item.call().equals(call)));
        assertThrows(IllegalArgumentException.class, () -> analysis.result().taintOf(call));
    }

    @Test
    void unknownAndUnresolvedExpressionsRemainUnknownWithoutTextGuessing() {
        Analysis unknown = analyze("unknownExpression", "input");
        Definition task = definition(unknown.dataFlow(), "task");
        assertEquals(TaintState.UNKNOWN, unknown.result().taintOf(task).state());
        assertEquals(
                TaintState.UNKNOWN,
                unknown.result().taintOf(useInCall(unknown.dataFlow(), "consume", "task")).state());
        assertTrue(unknown.result().unsupported().stream()
                .anyMatch(item -> item.construct().equals("lambda_expression")));
        assertTrue(unknown.dataFlow().useSites().stream()
                .noneMatch(use -> use.reference().name().equals("input")));

        Analysis unresolved = analyze("unresolvedReference");
        MethodCallExpression consume = methodCall(unresolved.dataFlow(), "consume");
        assertEquals(TaintState.UNKNOWN, unresolved.result().argumentTaint(consume, 0).state());
        assertTrue(unresolved.result().unsupported().stream()
                .anyMatch(item -> item.construct().equals("unresolved variable reference")));
    }

    @Test
    void preservesAllSeedOriginsAtMerge() {
        Analysis analysis = analyze("multipleSeeds", "left", "right");
        UseSite use = useInCall(analysis.dataFlow(), "consume", "value");
        TaintValue value = analysis.result().taintOf(use);

        assertEquals(TaintState.TAINTED, value.state());
        assertEquals(Set.of("seed:left", "seed:right"), value.origins().stream()
                .map(TaintSeed::id)
                .collect(Collectors.toSet()));
        TaintTrace trace = analysis.result().traceTo(use);
        assertEquals(2, trace.steps().stream()
                .filter(step -> step.kind() == TaintTraceStepKind.SEED)
                .count());
    }

    @Test
    void reconstructsSeedToFinalUseTraceWithoutDuplicateStaticSteps() {
        Analysis analysis = analyze("chain", "input");
        UseSite finalUse = useInCall(analysis.dataFlow(), "consume", "c");
        TaintTrace trace = analysis.result().traceTo(finalUse);
        Set<String> definitions = trace.steps().stream()
                .flatMap(step -> step.definition().stream())
                .map(definition -> definition.variable().name())
                .collect(Collectors.toSet());
        Set<String> uses = trace.steps().stream()
                .flatMap(step -> step.useSite().stream())
                .map(use -> use.reference().name())
                .collect(Collectors.toSet());

        assertEquals(Set.of("input", "a", "b", "c"), definitions);
        assertTrue(uses.containsAll(Set.of("input", "a", "b", "c")));
        assertEquals(
                trace.steps().stream().map(TaintTraceStep::id).collect(Collectors.toSet()).size(),
                trace.steps().size());
        assertTrue(trace.edges().size() < 32);
    }

    @Test
    void explicitExpressionSeedCanModelFutureSourceRule() {
        Prepared prepared = prepare("expressionSeed");
        MethodCallExpression external = methodCall(prepared.dataFlow(), "externalValue");
        ExpressionTaintSeed seed = new ExpressionTaintSeed("explicit-expression", external);
        TaintAnalysisResult result =
                new IntraproceduralTaintAnalysis().analyze(prepared.dataFlow(), List.of(seed));

        assertEquals(TaintState.TAINTED, result.taintOf(external).state());
        assertEquals(TaintState.TAINTED, result.taintOf(definition(prepared.dataFlow(), "value")).state());
        assertEquals(
                TaintState.TAINTED,
                result.taintOf(useInCall(prepared.dataFlow(), "consume", "value")).state());
    }

    private static Analysis analyze(String methodName, String... seededParameters) {
        Prepared prepared = prepare(methodName);
        List<TaintSeed> seeds = Arrays.stream(seededParameters)
                .map(name -> new DefinitionTaintSeed(
                        "seed:" + name, parameter(prepared.dataFlow(), name)))
                .map(TaintSeed.class::cast)
                .toList();
        TaintAnalysisResult result =
                new IntraproceduralTaintAnalysis().analyze(prepared.dataFlow(), seeds);
        assertSame(prepared.dataFlow(), result.dataFlow());
        assertEquals(prepared.dataFlow().definitions().size(), result.analyzedDefinitions().size());
        return new Analysis(prepared.dataFlow(), result);
    }

    private static Prepared prepare(String methodName) {
        MethodInfo method = methods.get(methodName);
        if (method == null) {
            throw new IllegalArgumentException("Missing fixture method: " + methodName);
        }
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult dataFlow = new ReachingDefinitionsAnalysis().analyze(graph);
        return new Prepared(dataFlow);
    }

    private static Definition parameter(DataFlowResult dataFlow, String name) {
        return dataFlow.definitions().stream()
                .filter(definition -> definition.kind() == DefinitionKind.PARAMETER)
                .filter(definition -> definition.variable().name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static Definition definition(DataFlowResult dataFlow, String name) {
        return definitions(dataFlow, name).stream()
                .filter(definition -> definition.kind() != DefinitionKind.PARAMETER)
                .findFirst()
                .orElseGet(() -> parameter(dataFlow, name));
    }

    private static List<Definition> definitions(DataFlowResult dataFlow, String name) {
        return dataFlow.definitions().stream()
                .filter(definition -> definition.variable().name().equals(name))
                .toList();
    }

    private static UseSite useInCall(DataFlowResult dataFlow, String methodName, String name) {
        return dataFlow.useSites().stream()
                .filter(use -> use.reference().name().equals(name))
                .filter(use -> methodCallName(use.statement()).equals(methodName))
                .findFirst()
                .orElseThrow();
    }

    private static MethodCallExpression methodCall(DataFlowResult dataFlow, String methodName) {
        return dataFlow.graph().reachableBlocks().stream()
                .map(block -> methodCallInBlockOrNull(block, methodName))
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElseThrow();
    }

    private static MethodCallExpression methodCallInBlock(BasicBlock block, String methodName) {
        MethodCallExpression call = methodCallInBlockOrNull(block, methodName);
        if (call == null) {
            throw new IllegalArgumentException("Method call not found: " + methodName);
        }
        return call;
    }

    private static MethodCallExpression methodCallInBlockOrNull(
            BasicBlock block, String methodName) {
        for (Statement statement : block.statements()) {
            if (statement instanceof ExpressionStatement expression
                    && expression.expression() instanceof MethodCallExpression call
                    && call.call().methodName().equals(methodName)) {
                return call;
            }
            if (statement instanceof com.totalsecurity.sast.ir.statement.VariableDeclarationStatement declaration) {
                for (var variable : declaration.variables()) {
                    if (variable.initializer().orElse(null) instanceof MethodCallExpression call
                            && call.call().methodName().equals(methodName)) {
                        return call;
                    }
                }
            }
        }
        return null;
    }

    private static BasicBlock blockCalling(ControlFlowGraph graph, String methodName) {
        return graph.blocks().stream()
                .filter(block -> methodCallInBlockOrNull(block, methodName) != null)
                .findFirst()
                .orElseThrow();
    }

    private static String methodCallName(Statement statement) {
        if (statement instanceof ExpressionStatement expression
                && expression.expression() instanceof MethodCallExpression call) {
            return call.call().methodName();
        }
        return "";
    }

    private static void assertState(TaintValue value, TaintState state, int originCount) {
        assertEquals(state, value.state());
        assertEquals(originCount, value.origins().size());
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = IntraproceduralTaintAnalysisTest.class
                .getClassLoader()
                .getResource("fixtures/TaintFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 5 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Prepared(DataFlowResult dataFlow) {}

    private record Analysis(DataFlowResult dataFlow, TaintAnalysisResult result) {}
}
