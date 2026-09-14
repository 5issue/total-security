package com.totalsecurity.sast.dataflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.cfg.ControlFlowGraphBuilder;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import com.totalsecurity.sast.java.extractor.JavaSemanticExtractor;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ReachingDefinitionsAnalysisTest {
    private static Map<String, MethodInfo> methods;

    @BeforeAll
    static void extractFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixturePath())) {
            assertFalse(parsedFile.hasSyntaxErrors());
            JavaFileInfo file = new JavaSemanticExtractor().extract(parsedFile);
            ClassInfo fixture = file.types().stream()
                    .filter(type -> type.name().equals("DataFlowFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = fixture.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, method -> method));
        }
    }

    @Test
    void createsParameterDefinitionsAtEntry() {
        Analysis analysis = analyze("chain");
        VariableSymbol input = symbol(analysis.result(), "input");
        Definition parameter = definition(analysis.result(), input, DefinitionKind.PARAMETER);

        assertTrue(analysis.result().inState(analysis.graph().entry()).orElseThrow().asMap().isEmpty());
        assertEquals(
                Set.of(parameter),
                analysis.result().outState(analysis.graph().entry()).orElseThrow().definitionsOf(input));
        assertTrue(parameter.assignedExpression().isEmpty());
        assertTrue(parameter.statement().isEmpty());
    }

    @Test
    void tracksSequentialVariableChainAndUseSites() {
        Analysis analysis = analyze("chain");
        Definition a = definition(analysis.result(), "a", DefinitionKind.VARIABLE_INITIALIZER);
        Definition b = definition(analysis.result(), "b", DefinitionKind.VARIABLE_INITIALIZER);
        Definition c = definition(analysis.result(), "c", DefinitionKind.VARIABLE_INITIALIZER);

        VariableReference aUse = (VariableReference) b.assignedExpression().orElseThrow();
        VariableReference bUse = (VariableReference) c.assignedExpression().orElseThrow();
        UseSite cUse = useInCall(analysis.result(), "execute", "c");

        assertEquals(Set.of(a), analysis.result().reachingDefinitions(aUse));
        assertEquals(Set.of(b), analysis.result().reachingDefinitions(bUse));
        assertEquals(Set.of(c), analysis.result().reachingDefinitions(cUse.reference()));
        assertSame(cUse.statement(), analysis.result().useSite(cUse.reference()).orElseThrow().statement());
    }

    @Test
    void killsPreviousDefinitionOnStraightLineOverwrite() {
        Analysis analysis = analyze("overwrite");
        VariableSymbol value = symbol(analysis.result(), "value");
        Definition initializer = definition(
                analysis.result(), value, DefinitionKind.VARIABLE_INITIALIZER);
        Definition assignment = definition(analysis.result(), value, DefinitionKind.ASSIGNMENT);
        UseSite use = useInCall(analysis.result(), "execute", "value");

        assertEquals(Set.of(assignment), analysis.result().reachingDefinitions(use.reference()));
        assertFalse(analysis.result().reachingDefinitions(use.reference()).contains(initializer));
        assertEquals(
                Set.of(assignment),
                analysis.result().stateBefore(use.statement()).orElseThrow().definitionsOf(value));
        assertEquals(Set.of(assignment),
                analysis.result().outState(use.block()).orElseThrow().definitionsOf(value));
    }

    @Test
    void extractsUsesFromBinaryExpression() {
        Analysis analysis = analyze("binary");
        Definition combined =
                definition(analysis.result(), "combined", DefinitionKind.VARIABLE_INITIALIZER);
        BinaryExpression binary = (BinaryExpression) combined.assignedExpression().orElseThrow();
        VariableReference left = (VariableReference) binary.left();
        VariableReference right = (VariableReference) binary.right();

        assertEquals(
                Set.of(definition(analysis.result(), "left", DefinitionKind.PARAMETER)),
                analysis.result().reachingDefinitions(left));
        assertEquals(
                Set.of(definition(analysis.result(), "right", DefinitionKind.PARAMETER)),
                analysis.result().reachingDefinitions(right));
        assertEquals(
                Set.of(combined),
                analysis.result().reachingDefinitions(
                        useInCall(analysis.result(), "execute", "combined").reference()));
    }

    @Test
    void unionsBranchDefinitionsAtMerge() {
        Analysis analysis = analyze("branchMerge");
        VariableSymbol value = symbol(analysis.result(), "value");
        Set<Definition> assignments = definitions(
                analysis.result(), value, DefinitionKind.ASSIGNMENT);
        UseSite use = useInCall(analysis.result(), "execute", "value");

        assertEquals(2, assignments.size());
        assertEquals(assignments, analysis.result().inState(use.block()).orElseThrow().definitionsOf(value));
        assertEquals(assignments, analysis.result().reachingDefinitions(use.reference()));
    }

    @Test
    void mergesOriginalAndBranchDefinitionWithoutElse() {
        Analysis analysis = analyze("ifWithoutElse");
        VariableSymbol value = symbol(analysis.result(), "value");
        Definition initializer = definition(
                analysis.result(), value, DefinitionKind.VARIABLE_INITIALIZER);
        Definition branch = definition(analysis.result(), value, DefinitionKind.ASSIGNMENT);
        UseSite use = useInCall(analysis.result(), "execute", "value");

        assertEquals(
                Set.of(initializer, branch),
                analysis.result().inState(use.block()).orElseThrow().definitionsOf(value));
        assertEquals(
                Set.of(initializer, branch),
                analysis.result().reachingDefinitions(use.reference()));
    }

    @Test
    void earlyReturnPathDoesNotPolluteContinuingUse() {
        Analysis analysis = analyze("earlyReturn");
        VariableSymbol value = symbol(analysis.result(), "value");
        Definition initializer = definition(
                analysis.result(), value, DefinitionKind.VARIABLE_INITIALIZER);
        Definition assignment = definition(analysis.result(), value, DefinitionKind.ASSIGNMENT);
        UseSite use = useInCall(analysis.result(), "execute", "value");

        assertEquals(Set.of(assignment), analysis.result().reachingDefinitions(use.reference()));
        assertFalse(analysis.result().stateBefore(use.statement()).orElseThrow()
                .definitionsOf(value).contains(initializer));
    }

    @Test
    void convergesWhileLoopAndPropagatesLoopDefinitionAfterward() {
        Analysis analysis = analyze("whileFlow");
        VariableSymbol value = symbol(analysis.result(), "value");
        Definition initializer = definition(
                analysis.result(), value, DefinitionKind.VARIABLE_INITIALIZER);
        Definition loopAssignment = definition(analysis.result(), value, DefinitionKind.ASSIGNMENT);
        BasicBlock condition = controlBlock(analysis.graph(), WhileStatement.class);
        UseSite afterLoop = useInCall(analysis.result(), "execute", "value");

        assertEquals(
                Set.of(initializer, loopAssignment),
                analysis.result().inState(condition).orElseThrow().definitionsOf(value));
        assertEquals(
                Set.of(initializer, loopAssignment),
                analysis.result().reachingDefinitions(afterLoop.reference()));
        assertTrue(analysis.result().evaluationCount(condition) > 1);
    }

    @Test
    void convergesForInitializerUpdateAndBodyDefinitions() {
        Analysis analysis = analyze("forFlow");
        ForStatement loop = controlStatement(analysis.graph(), ForStatement.class);
        BasicBlock condition = controlBlock(analysis.graph(), ForStatement.class);
        VariableSymbol index = symbol(analysis.result(), "i");
        Definition indexInitializer = definition(
                analysis.result(), index, DefinitionKind.VARIABLE_INITIALIZER);
        Definition indexUpdate = definition(analysis.result(), index, DefinitionKind.ASSIGNMENT);
        VariableSymbol value = symbol(analysis.result(), "value");
        Definition valueInitializer = definition(
                analysis.result(), value, DefinitionKind.VARIABLE_INITIALIZER);
        Definition bodyAssignment = definition(analysis.result(), value, DefinitionKind.ASSIGNMENT);
        UseSite afterLoop = useInCall(analysis.result(), "execute", "value");

        assertFalse(loop.updates().isEmpty());
        assertEquals(
                Set.of(indexInitializer, indexUpdate),
                analysis.result().inState(condition).orElseThrow().definitionsOf(index));
        assertEquals(
                Set.of(valueInitializer, bodyAssignment),
                analysis.result().reachingDefinitions(afterLoop.reference()));
        assertTrue(analysis.result().evaluationCount(condition) > 1);
    }

    @Test
    void excludesUnreachableDefinitionsAndUses() {
        Analysis analysis = analyze("unreachable");
        VariableSymbol value = symbol(analysis.result(), "value");
        BasicBlock unreachableCall = blockCalling(analysis.graph(), "execute");

        assertTrue(analysis.result().definitionsFor(value).isEmpty());
        assertTrue(analysis.result().inState(unreachableCall).isEmpty());
        assertTrue(analysis.result().useSites().stream()
                .noneMatch(use -> use.block().equals(unreachableCall)));
        assertFalse(analysis.graph().reachableBlocks().contains(unreachableCall));
    }

    @Test
    void declarationWithoutInitializerDoesNotInventDefinition() {
        Analysis analysis = analyze("noInitializer");
        VariableSymbol value = symbol(analysis.result(), "value");
        UseSite use = useInCall(analysis.result(), "execute", "value");

        assertTrue(analysis.result().definitionsFor(value).isEmpty());
        assertTrue(analysis.result().reachingDefinitions(use.reference()).isEmpty());
    }

    @Test
    void distinguishesSameNameDeclarationsInSiblingScopes() {
        Analysis analysis = analyze("siblingScopes");
        List<VariableSymbol> values = analysis.result().symbols().stream()
                .filter(symbol -> symbol.name().equals("value"))
                .sorted(Comparator.comparingInt(VariableSymbol::id))
                .toList();
        List<UseSite> uses = analysis.result().useSites().stream()
                .filter(use -> use.reference().name().equals("value"))
                .sorted(Comparator.comparingInt(use -> use.reference().location().startLine()))
                .toList();

        assertEquals(2, values.size());
        assertNotEquals(values.get(0), values.get(1));
        assertNotEquals(values.get(0).declarationLocation(), values.get(1).declarationLocation());
        assertEquals(values.get(0), uses.get(0).variable());
        assertEquals(values.get(1), uses.get(1).variable());
        assertEquals(
                definitions(analysis.result(), values.get(0), DefinitionKind.VARIABLE_INITIALIZER),
                analysis.result().reachingDefinitions(uses.get(0).reference()));
        assertEquals(
                definitions(analysis.result(), values.get(1), DefinitionKind.VARIABLE_INITIALIZER),
                analysis.result().reachingDefinitions(uses.get(1).reference()));
    }

    @Test
    void extractsSupportedNestedExpressionUsesStructurally() {
        Analysis analysis = analyze("expressionShapes");
        Definition combined =
                definition(analysis.result(), "combined", DefinitionKind.VARIABLE_INITIALIZER);
        assertTrue(combined.assignedExpression().orElseThrow() instanceof ParenthesizedExpression);

        Map<String, Long> useCounts = analysis.result().useSites().stream()
                .collect(Collectors.groupingBy(
                        use -> use.reference().name(), Collectors.counting()));
        assertEquals(2L, useCounts.get("worker"));
        assertEquals(2L, useCounts.get("input"));
        assertEquals(1L, useCounts.get("suffix"));
        assertEquals(1L, useCounts.get("combined"));
        assertEquals(1L, useCounts.get("holder"));
        assertTrue(analysis.result().useSites().stream()
                .allMatch(use -> !analysis.result().reachingDefinitions(use.reference()).isEmpty()));
    }

    @Test
    void recordsUnknownAndUnresolvedInputsWithoutGuessingSourceText() {
        Analysis unknown = analyze("unknownExpression");
        assertTrue(unknown.result().unsupportedDataFlow().stream()
                .anyMatch(item -> item.construct().equals("lambda_expression")));
        assertTrue(unknown.result().useSites().stream()
                .noneMatch(use -> use.reference().name().equals("input")));

        Analysis unresolved = analyze("unresolvedReference");
        assertEquals(1, unresolved.result().unresolvedReferences().size());
        assertEquals(
                "missing",
                unresolved.result().unresolvedReferences().getFirst().reference().name());
        assertTrue(unresolved.result().useSites().isEmpty());
    }

    private static Analysis analyze(String methodName) {
        MethodInfo method = methods.get(methodName);
        if (method == null) {
            throw new IllegalArgumentException("Missing fixture method: " + methodName);
        }
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        DataFlowResult result = new ReachingDefinitionsAnalysis().analyze(graph);
        assertSame(graph, result.graph());
        assertEquals(graph.reachableBlocks(), result.inStates().keySet());
        assertEquals(graph.reachableBlocks(), result.outStates().keySet());
        return new Analysis(graph, result);
    }

    private static VariableSymbol symbol(DataFlowResult result, String name) {
        return result.symbols().stream()
                .filter(symbol -> symbol.name().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static Definition definition(
            DataFlowResult result, String variableName, DefinitionKind kind) {
        return definition(result, symbol(result, variableName), kind);
    }

    private static Definition definition(
            DataFlowResult result, VariableSymbol variable, DefinitionKind kind) {
        return definitions(result, variable, kind).stream().findFirst().orElseThrow();
    }

    private static Set<Definition> definitions(
            DataFlowResult result, VariableSymbol variable, DefinitionKind kind) {
        return result.definitionsFor(variable).stream()
                .filter(definition -> definition.kind() == kind)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static UseSite useInCall(
            DataFlowResult result, String methodName, String variableName) {
        return result.useSites().stream()
                .filter(use -> use.reference().name().equals(variableName))
                .filter(use -> methodCallName(use.statement()).equals(methodName))
                .findFirst()
                .orElseThrow();
    }

    private static String methodCallName(Statement statement) {
        if (statement instanceof ExpressionStatement expressionStatement
                && expressionStatement.expression() instanceof MethodCallExpression call) {
            return call.call().methodName();
        }
        return "";
    }

    private static BasicBlock blockCalling(ControlFlowGraph graph, String methodName) {
        return graph.blocks().stream()
                .filter(block -> block.statements().stream()
                        .anyMatch(statement -> methodCallName(statement).equals(methodName)))
                .findFirst()
                .orElseThrow();
    }

    private static <T extends Statement> BasicBlock controlBlock(
            ControlFlowGraph graph, Class<T> type) {
        T statement = controlStatement(graph, type);
        return graph.blocks().stream()
                .filter(block -> block.controlStatement().orElse(null) == statement)
                .findFirst()
                .orElseThrow();
    }

    private static <T extends Statement> T controlStatement(
            ControlFlowGraph graph, Class<T> type) {
        return graph.blocks().stream()
                .map(BasicBlock::controlStatement)
                .flatMap(java.util.Optional::stream)
                .filter(type::isInstance)
                .map(type::cast)
                .findFirst()
                .orElseThrow();
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = ReachingDefinitionsAnalysisTest.class
                .getClassLoader()
                .getResource("fixtures/DataFlowFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 4 fixture not found");
        }
        return Path.of(resource.toURI());
    }

    private record Analysis(ControlFlowGraph graph, DataFlowResult result) {}
}
