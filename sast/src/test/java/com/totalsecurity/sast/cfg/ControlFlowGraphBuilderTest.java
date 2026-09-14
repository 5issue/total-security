package com.totalsecurity.sast.cfg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.statement.BlockStatement;
import com.totalsecurity.sast.ir.statement.BreakStatement;
import com.totalsecurity.sast.ir.statement.ContinueStatement;
import com.totalsecurity.sast.ir.statement.DoWhileStatement;
import com.totalsecurity.sast.ir.statement.EnhancedForStatement;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.IfStatement;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.UnknownStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import com.totalsecurity.sast.parser.JavaSourceParser;
import com.totalsecurity.sast.parser.ParsedJavaFile;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ControlFlowGraphBuilderTest {
    private static Map<String, MethodInfo> methods;

    @BeforeAll
    static void extractFixture() throws Exception {
        try (JavaSourceParser parser = new JavaSourceParser();
                ParsedJavaFile parsedFile = parser.parse(fixturePath())) {
            assertFalse(parsedFile.hasSyntaxErrors());
            JavaFileInfo file = new com.totalsecurity.sast.java.extractor.JavaSemanticExtractor()
                    .extract(parsedFile);
            ClassInfo fixture = file.types().stream()
                    .filter(type -> type.name().equals("CfgFixture"))
                    .findFirst()
                    .orElseThrow();
            methods = fixture.methods().stream()
                    .collect(Collectors.toUnmodifiableMap(MethodInfo::name, method -> method));
        }
    }

    @Test
    void groupsStraightLineStatementsAndConnectsEntryAndExit() {
        MethodInfo method = method("sequential");
        ControlFlowGraph graph = build(method);
        List<Statement> sourceStatements = method.body().orElseThrow().statements();

        BasicBlock straightLine = graph.blockContaining(sourceStatements.getFirst()).orElseThrow();
        assertEquals(sourceStatements, straightLine.statements());
        assertEquals(List.of(straightLine), graph.successors(graph.entry()));
        assertEquals(List.of(graph.entry()), graph.predecessors(straightLine));
        assertEdge(graph, graph.entry(), straightLine, CfgEdgeType.NORMAL);
        assertEdge(graph, straightLine, graph.exit(), CfgEdgeType.NORMAL);
        assertTrue(graph.reachableBlocks().containsAll(graph.blocks()));
    }

    @Test
    void buildsIfWithoutElseAndMergeFlow() {
        MethodInfo method = method("ifWithoutElse");
        ControlFlowGraph graph = build(method);
        IfStatement conditional = statement(method, IfStatement.class, ignored -> true);
        BasicBlock condition = controlBlock(graph, conditional);
        Statement thenStatement = ((BlockStatement) conditional.thenBranch()).statements().getFirst();
        BasicBlock thenBlock = graph.blockContaining(thenStatement).orElseThrow();
        ReturnStatement returned = statement(method, ReturnStatement.class, ignored -> true);
        BasicBlock returnBlock = graph.blockContaining(returned).orElseThrow();

        assertEdge(graph, condition, thenBlock, CfgEdgeType.TRUE_BRANCH);
        assertEdge(graph, condition, returnBlock, CfgEdgeType.FALSE_BRANCH);
        assertTrue(graph.incomingEdges(returnBlock).stream()
                .anyMatch(edge -> edge.type() == CfgEdgeType.NORMAL));
        assertEdge(graph, returnBlock, graph.exit(), CfgEdgeType.RETURN);
    }

    @Test
    void buildsNestedIfAndDoesNotMergeTerminatedBranches() {
        MethodInfo method = method("branches");
        ControlFlowGraph graph = build(method);
        List<BasicBlock> conditions = graph.blocks().stream()
                .filter(block -> block.controlStatement().orElse(null) instanceof IfStatement)
                .sorted(Comparator.comparingInt(BasicBlock::id))
                .toList();

        assertEquals(2, conditions.size());
        assertOutgoingType(graph, conditions.get(0), CfgEdgeType.TRUE_BRANCH);
        assertOutgoingType(graph, conditions.get(0), CfgEdgeType.FALSE_BRANCH);
        assertOutgoingType(graph, conditions.get(1), CfgEdgeType.TRUE_BRANCH);
        assertOutgoingType(graph, conditions.get(1), CfgEdgeType.FALSE_BRANCH);

        List<ReturnStatement> returns = statements(method, ReturnStatement.class);
        assertEquals(3, returns.size());
        for (ReturnStatement returned : returns) {
            BasicBlock block = graph.blockContaining(returned).orElseThrow();
            assertEquals(List.of(CfgEdgeType.RETURN),
                    graph.outgoingEdges(block).stream().map(CfgEdge::type).toList());
            assertSame(graph.exit(), graph.outgoingEdges(block).getFirst().target());
        }
    }

    @Test
    void preventsNormalFlowAfterEarlyReturn() {
        MethodInfo method = method("earlyReturn");
        ControlFlowGraph graph = build(method);
        ReturnStatement early = statements(method, ReturnStatement.class).getFirst();
        BasicBlock earlyBlock = graph.blockContaining(early).orElseThrow();

        assertEquals(List.of(CfgEdgeType.RETURN),
                graph.outgoingEdges(earlyBlock).stream().map(CfgEdge::type).toList());
        assertSame(graph.exit(), graph.outgoingEdges(earlyBlock).getFirst().target());
        BasicBlock workBlock = blockCalling(graph, "work");
        assertFalse(graph.edgesBetween(earlyBlock, workBlock).stream()
                .anyMatch(edge -> edge.type() == CfgEdgeType.NORMAL));
    }

    @Test
    void buildsWhileBranchesLoopBackBreakAndContinue() {
        MethodInfo method = method("whileFlow");
        ControlFlowGraph graph = build(method);
        WhileStatement loop = statement(method, WhileStatement.class, ignored -> true);
        BasicBlock condition = controlBlock(graph, loop);
        BasicBlock normalBodyEnd = blockCalling(graph, "work");
        CfgEdge falseEdge = outgoing(graph, condition, CfgEdgeType.FALSE_BRANCH);

        assertOutgoingType(graph, condition, CfgEdgeType.TRUE_BRANCH);
        assertEdge(graph, normalBodyEnd, condition, CfgEdgeType.LOOP_BACK);

        BreakStatement breakStatement = statement(method, BreakStatement.class, ignored -> true);
        BasicBlock breakBlock = graph.blockContaining(breakStatement).orElseThrow();
        assertEdge(graph, breakBlock, falseEdge.target(), CfgEdgeType.BREAK);

        ContinueStatement continueStatement =
                statement(method, ContinueStatement.class, ignored -> true);
        BasicBlock continueBlock = graph.blockContaining(continueStatement).orElseThrow();
        assertEdge(graph, continueBlock, condition, CfgEdgeType.CONTINUE);
    }

    @Test
    void buildsClassicForInitializerConditionUpdateAndContinueTarget() {
        MethodInfo method = method("forFlow");
        ControlFlowGraph graph = build(method);
        ForStatement loop = statement(method, ForStatement.class, ignored -> true);
        BasicBlock condition = controlBlock(graph, loop);
        BasicBlock update = graph.blocks().stream()
                .filter(block -> block.kind() == BasicBlockKind.LOOP_UPDATE)
                .findFirst()
                .orElseThrow();
        BasicBlock initializer = graph.blockContaining(loop.initializers().getFirst()).orElseThrow();

        assertEdge(graph, initializer, condition, CfgEdgeType.NORMAL);
        assertOutgoingType(graph, condition, CfgEdgeType.TRUE_BRANCH);
        assertOutgoingType(graph, condition, CfgEdgeType.FALSE_BRANCH);
        assertEdge(graph, update, condition, CfgEdgeType.LOOP_BACK);

        ContinueStatement continued = statement(method, ContinueStatement.class, ignored -> true);
        BasicBlock continueBlock = graph.blockContaining(continued).orElseThrow();
        assertEdge(graph, continueBlock, update, CfgEdgeType.CONTINUE);
    }

    @Test
    void targetsConditionWhenClassicForContinueHasNoUpdate() {
        MethodInfo method = method("forWithoutUpdate");
        ControlFlowGraph graph = build(method);
        ForStatement loop = statement(method, ForStatement.class, ignored -> true);
        BasicBlock condition = controlBlock(graph, loop);
        ContinueStatement continued = statement(method, ContinueStatement.class, ignored -> true);
        BasicBlock continueBlock = graph.blockContaining(continued).orElseThrow();

        assertTrue(loop.updates().isEmpty());
        assertEdge(graph, continueBlock, condition, CfgEdgeType.CONTINUE);
    }

    @Test
    void buildsDoWhileWithBodyBeforeCondition() {
        MethodInfo method = method("doFlow");
        ControlFlowGraph graph = build(method);
        DoWhileStatement loop = statement(method, DoWhileStatement.class, ignored -> true);
        BasicBlock condition = controlBlock(graph, loop);
        BasicBlock body = blockCalling(graph, "work");

        assertTrue(graph.reachableBlocks().contains(body));
        assertFalse(graph.edgesBetween(graph.entry(), condition).stream()
                .anyMatch(edge -> edge.type() == CfgEdgeType.NORMAL));
        assertTrue(graph.predecessors(condition).contains(body));
        assertEdge(graph, condition, body, CfgEdgeType.LOOP_BACK);
        assertOutgoingType(graph, condition, CfgEdgeType.FALSE_BRANCH);
    }

    @Test
    void buildsAbstractEnhancedForIterationFlow() {
        MethodInfo method = method("enhancedFlow");
        ControlFlowGraph graph = build(method);
        EnhancedForStatement loop = statement(method, EnhancedForStatement.class, ignored -> true);
        BasicBlock iteration = controlBlock(graph, loop);
        BasicBlock body = blockCalling(graph, "work");

        assertEdge(graph, iteration, body, CfgEdgeType.TRUE_BRANCH);
        assertOutgoingType(graph, iteration, CfgEdgeType.FALSE_BRANCH);
        assertEdge(graph, body, iteration, CfgEdgeType.LOOP_BACK);
    }

    @Test
    void buildsSwitchCaseDefaultFallThroughAndBreak() {
        MethodInfo method = method("switchFlow");
        ControlFlowGraph graph = build(method);
        SwitchStatement selection = statement(method, SwitchStatement.class, ignored -> true);
        BasicBlock selector = controlBlock(graph, selection);
        BasicBlock first = blockCalling(graph, "first");
        BasicBlock second = blockCalling(graph, "second");
        BasicBlock other = blockCalling(graph, "other");

        assertEquals(2, graph.outgoingEdges(selector).stream()
                .filter(edge -> edge.type() == CfgEdgeType.SWITCH_CASE)
                .count());
        assertEquals(1, graph.outgoingEdges(selector).stream()
                .filter(edge -> edge.type() == CfgEdgeType.SWITCH_DEFAULT)
                .count());
        assertEdge(graph, first, second, CfgEdgeType.NORMAL);

        BreakStatement broken = statement(method, BreakStatement.class, ignored -> true);
        BasicBlock breakBlock = graph.blockContaining(broken).orElseThrow();
        CfgEdge breakEdge = outgoing(graph, breakBlock, CfgEdgeType.BREAK);
        assertNotEquals(selector, breakEdge.target());
        assertTrue(graph.successors(other).contains(breakEdge.target()));
    }

    @Test
    void targetsNearestSwitchBreakInsideLoopAndLoopContinue() {
        MethodInfo method = method("nestedLoopSwitch");
        ControlFlowGraph graph = build(method);
        WhileStatement loop = statement(method, WhileStatement.class, ignored -> true);
        BasicBlock loopCondition = controlBlock(graph, loop);
        SwitchStatement selection = statement(method, SwitchStatement.class, ignored -> true);
        BasicBlock selector = controlBlock(graph, selection);
        BreakStatement broken = statement(method, BreakStatement.class, ignored -> true);
        ContinueStatement continued = statement(method, ContinueStatement.class, ignored -> true);
        BasicBlock breakBlock = graph.blockContaining(broken).orElseThrow();
        BasicBlock continueBlock = graph.blockContaining(continued).orElseThrow();
        BasicBlock breakTarget = outgoing(graph, breakBlock, CfgEdgeType.BREAK).target();

        assertNotEquals(outgoing(graph, loopCondition, CfgEdgeType.FALSE_BRANCH).target(), breakTarget);
        assertNotEquals(selector, breakTarget);
        assertSame(continueBlock, breakTarget);
        assertEdge(graph, continueBlock, loopCondition, CfgEdgeType.CONTINUE);
    }

    @Test
    void terminatesThrowAndLeavesFollowingStatementUnreachable() {
        MethodInfo method = method("throwing");
        ControlFlowGraph graph = build(method);
        ThrowStatement thrown = statement(method, ThrowStatement.class, ignored -> true);
        BasicBlock throwBlock = graph.blockContaining(thrown).orElseThrow();
        BasicBlock afterBlock = blockCalling(graph, "after");

        assertEquals(List.of(CfgEdgeType.THROW),
                graph.outgoingEdges(throwBlock).stream().map(CfgEdge::type).toList());
        assertSame(graph.exit(), graph.outgoingEdges(throwBlock).getFirst().target());
        assertFalse(graph.reachableBlocks().contains(afterBlock));
        assertTrue(graph.edgesBetween(throwBlock, afterBlock).isEmpty());
    }

    @Test
    void reportsUnknownStatementsWhilePreservingSequentialOrder() {
        MethodInfo method = method("unknownFlow");
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        UnknownStatement unknown = statement(method, UnknownStatement.class, ignored -> true);
        BasicBlock block = graph.blockContaining(unknown).orElseThrow();

        assertEquals(1, graph.unsupportedControlFlow().size());
        assertEquals("synchronized_statement", graph.unsupportedControlFlow().getFirst().construct());
        assertEquals(unknown, block.statements().getFirst());
        assertEquals("after", methodCallName(block.statements().get(1)));
    }

    private static ControlFlowGraph build(MethodInfo method) {
        ControlFlowGraph graph = new ControlFlowGraphBuilder().build(method);
        assertSame(method, graph.method());
        assertEquals(BasicBlockKind.ENTRY, graph.entry().kind());
        assertEquals(BasicBlockKind.EXIT, graph.exit().kind());
        assertTrue(graph.unsupportedControlFlow().isEmpty());
        return graph;
    }

    private static MethodInfo method(String name) {
        MethodInfo method = methods.get(name);
        if (method == null) {
            throw new IllegalArgumentException("Missing fixture method: " + name);
        }
        return method;
    }

    private static BasicBlock controlBlock(ControlFlowGraph graph, Statement control) {
        return graph.blocks().stream()
                .filter(block -> block.controlStatement().orElse(null) == control)
                .findFirst()
                .orElseThrow();
    }

    private static BasicBlock blockCalling(ControlFlowGraph graph, String methodName) {
        return graph.blocks().stream()
                .filter(block -> block.statements().stream()
                        .anyMatch(statement -> methodCallName(statement).equals(methodName)))
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

    private static CfgEdge outgoing(
            ControlFlowGraph graph, BasicBlock source, CfgEdgeType type) {
        return graph.outgoingEdges(source).stream()
                .filter(edge -> edge.type() == type)
                .findFirst()
                .orElseThrow();
    }

    private static void assertOutgoingType(
            ControlFlowGraph graph, BasicBlock source, CfgEdgeType type) {
        assertTrue(graph.outgoingEdges(source).stream().anyMatch(edge -> edge.type() == type));
    }

    private static void assertEdge(
            ControlFlowGraph graph,
            BasicBlock source,
            BasicBlock target,
            CfgEdgeType type) {
        assertTrue(graph.edgesBetween(source, target).stream()
                .anyMatch(edge -> edge.type() == type));
    }

    private static <T extends Statement> T statement(
            MethodInfo method, Class<T> type, Predicate<T> predicate) {
        return statements(method, type).stream().filter(predicate).findFirst().orElseThrow();
    }

    private static <T extends Statement> List<T> statements(MethodInfo method, Class<T> type) {
        List<T> matches = new java.util.ArrayList<>();
        collect(method.body().orElseThrow(), type, matches);
        return List.copyOf(matches);
    }

    private static <T extends Statement> void collect(
            Statement statement, Class<T> type, List<T> matches) {
        if (type.isInstance(statement)) {
            matches.add(type.cast(statement));
        }
        switch (statement) {
            case com.totalsecurity.sast.ir.statement.BlockStatement block ->
                    block.statements().forEach(child -> collect(child, type, matches));
            case IfStatement conditional -> {
                collect(conditional.thenBranch(), type, matches);
                conditional.elseBranch().ifPresent(child -> collect(child, type, matches));
            }
            case WhileStatement loop -> collect(loop.body(), type, matches);
            case DoWhileStatement loop -> collect(loop.body(), type, matches);
            case ForStatement loop -> collect(loop.body(), type, matches);
            case EnhancedForStatement loop -> collect(loop.body(), type, matches);
            case SwitchStatement selection -> selection.cases().forEach(switchCase ->
                    switchCase.statements().forEach(child -> collect(child, type, matches)));
            default -> {
                // Leaf statement.
            }
        }
    }

    private static Path fixturePath() throws URISyntaxException {
        var resource = ControlFlowGraphBuilderTest.class
                .getClassLoader()
                .getResource("fixtures/CfgFixture.java");
        if (resource == null) {
            throw new IllegalStateException("STEP 3 fixture not found");
        }
        return Path.of(resource.toURI());
    }
}
