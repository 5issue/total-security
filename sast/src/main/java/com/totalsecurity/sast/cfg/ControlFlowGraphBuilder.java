package com.totalsecurity.sast.cfg;

import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
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
import com.totalsecurity.sast.ir.statement.SwitchCase;
import com.totalsecurity.sast.ir.statement.SwitchCaseKind;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.UnknownStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Builds method-level CFGs exclusively from the Tree-sitter-independent Java IR. */
public final class ControlFlowGraphBuilder {
    private MethodInfo method;
    private MutableBlock entry;
    private MutableBlock exit;
    private int nextBlockId;
    private final List<MutableBlock> blocks = new ArrayList<>();
    private final List<MutableEdge> edges = new ArrayList<>();
    private final List<UnsupportedControlFlow> unsupported = new ArrayList<>();
    private final Deque<ControlContext> controlContexts = new ArrayDeque<>();

    public ControlFlowGraph build(MethodInfo methodInfo) {
        reset(Objects.requireNonNull(methodInfo, "methodInfo"));
        entry = newBlock(BasicBlockKind.ENTRY, "entry", method.location(), Optional.empty());
        exit = newBlock(BasicBlockKind.EXIT, "exit", method.location(), Optional.empty());

        List<Pending> frontier = List.of(pending(entry, CfgEdgeType.NORMAL, method.location()));
        if (method.body().isPresent()) {
            frontier = buildStatements(method.body().orElseThrow().statements(), frontier);
        }
        connect(frontier, exit);
        return freeze();
    }

    private void reset(MethodInfo methodInfo) {
        method = methodInfo;
        entry = null;
        exit = null;
        nextBlockId = 0;
        blocks.clear();
        edges.clear();
        unsupported.clear();
        controlContexts.clear();
    }

    private List<Pending> buildStatements(List<Statement> statements, List<Pending> incoming) {
        List<Pending> frontier = incoming;
        for (Statement statement : statements) {
            frontier = buildStatement(statement, frontier);
        }
        return frontier;
    }

    private List<Pending> buildStatement(Statement statement, List<Pending> incoming) {
        return switch (statement) {
            case BlockStatement block -> buildStatements(block.statements(), incoming);
            case VariableDeclarationStatement ignored -> appendSequential(statement, incoming);
            case ExpressionStatement ignored -> appendSequential(statement, incoming);
            case UnknownStatement unknown -> {
                unsupported.add(new UnsupportedControlFlow(
                        unknown.syntaxKind(),
                        "Unknown statement is retained sequentially without inferred control flow",
                        unknown.location()));
                yield appendSequential(statement, incoming);
            }
            case ReturnStatement ignored -> terminateAtExit(statement, incoming, CfgEdgeType.RETURN);
            case ThrowStatement ignored -> terminateAtExit(statement, incoming, CfgEdgeType.THROW);
            case BreakStatement breakStatement -> buildBreak(breakStatement, incoming);
            case ContinueStatement continueStatement -> buildContinue(continueStatement, incoming);
            case IfStatement ifStatement -> buildIf(ifStatement, incoming);
            case WhileStatement whileStatement -> buildWhile(whileStatement, incoming);
            case DoWhileStatement doWhileStatement -> buildDoWhile(doWhileStatement, incoming);
            case ForStatement forStatement -> buildFor(forStatement, incoming);
            case EnhancedForStatement enhancedFor -> buildEnhancedFor(enhancedFor, incoming);
            case SwitchStatement switchStatement -> buildSwitch(switchStatement, incoming);
        };
    }

    private List<Pending> appendSequential(Statement statement, List<Pending> incoming) {
        MutableBlock block = appendableBlock(incoming).orElseGet(() -> {
            MutableBlock created = newBlock(
                    BasicBlockKind.STATEMENTS,
                    "statements",
                    statement.location(),
                    Optional.empty());
            connect(incoming, created);
            return created;
        });
        block.statements.add(statement);
        return List.of(pending(block, CfgEdgeType.NORMAL, statement.location()));
    }

    private Optional<MutableBlock> appendableBlock(List<Pending> frontier) {
        if (frontier.size() != 1 || frontier.getFirst().type != CfgEdgeType.NORMAL) {
            return Optional.empty();
        }
        MutableBlock candidate = frontier.getFirst().source;
        return candidate.canAppend() ? Optional.of(candidate) : Optional.empty();
    }

    private List<Pending> terminateAtExit(
            Statement statement, List<Pending> incoming, CfgEdgeType edgeType) {
        MutableBlock block = appendTerminal(statement, incoming);
        addEdge(block, exit, edgeType, statement.location());
        return List.of();
    }

    private List<Pending> buildBreak(BreakStatement statement, List<Pending> incoming) {
        MutableBlock block = appendTerminal(statement, incoming);
        if (statement.label().isPresent()) {
            unsupported.add(new UnsupportedControlFlow(
                    "labeled break",
                    "Labeled control targets are not modeled",
                    statement.location()));
            return List.of();
        }
        Optional<MutableBlock> target = nearestBreakTarget();
        if (target.isEmpty()) {
            unsupported.add(new UnsupportedControlFlow(
                    "break", "No enclosing loop or switch target", statement.location()));
            return List.of();
        }
        addEdge(block, target.orElseThrow(), CfgEdgeType.BREAK, statement.location());
        return List.of();
    }

    private List<Pending> buildContinue(ContinueStatement statement, List<Pending> incoming) {
        MutableBlock block = appendTerminal(statement, incoming);
        if (statement.label().isPresent()) {
            unsupported.add(new UnsupportedControlFlow(
                    "labeled continue",
                    "Labeled control targets are not modeled",
                    statement.location()));
            return List.of();
        }
        Optional<MutableBlock> target = nearestContinueTarget();
        if (target.isEmpty()) {
            unsupported.add(new UnsupportedControlFlow(
                    "continue", "No enclosing loop target", statement.location()));
            return List.of();
        }
        addEdge(block, target.orElseThrow(), CfgEdgeType.CONTINUE, statement.location());
        return List.of();
    }

    private MutableBlock appendTerminal(Statement statement, List<Pending> incoming) {
        MutableBlock block = appendableBlock(incoming).orElseGet(() -> {
            MutableBlock created = newBlock(
                    BasicBlockKind.STATEMENTS,
                    "terminal",
                    statement.location(),
                    Optional.empty());
            connect(incoming, created);
            return created;
        });
        block.statements.add(statement);
        block.terminated = true;
        return block;
    }

    private List<Pending> buildIf(IfStatement statement, List<Pending> incoming) {
        MutableBlock condition = newBlock(
                BasicBlockKind.CONDITION,
                "if.condition",
                statement.location(),
                Optional.of(statement));
        connect(incoming, condition);

        MutableBlock thenEntry = newBlock(
                BasicBlockKind.STATEMENTS,
                "if.then",
                statement.thenBranch().location(),
                Optional.empty());
        addEdge(condition, thenEntry, CfgEdgeType.TRUE_BRANCH, statement.location());
        List<Pending> thenFrontier = buildStatement(
                statement.thenBranch(),
                List.of(pending(thenEntry, CfgEdgeType.NORMAL, statement.thenBranch().location())));

        List<Pending> elseFrontier;
        if (statement.elseBranch().isPresent()) {
            Statement elseBranch = statement.elseBranch().orElseThrow();
            MutableBlock elseEntry = newBlock(
                    BasicBlockKind.STATEMENTS,
                    "if.else",
                    elseBranch.location(),
                    Optional.empty());
            addEdge(condition, elseEntry, CfgEdgeType.FALSE_BRANCH, statement.location());
            elseFrontier = buildStatement(
                    elseBranch,
                    List.of(pending(elseEntry, CfgEdgeType.NORMAL, elseBranch.location())));
        } else {
            elseFrontier = List.of(pending(
                    condition, CfgEdgeType.FALSE_BRANCH, statement.location()));
        }

        List<Pending> combined = new ArrayList<>(thenFrontier.size() + elseFrontier.size());
        combined.addAll(thenFrontier);
        combined.addAll(elseFrontier);
        return List.copyOf(combined);
    }

    private List<Pending> buildWhile(WhileStatement statement, List<Pending> incoming) {
        MutableBlock condition = newBlock(
                BasicBlockKind.LOOP_HEADER,
                "while.condition",
                statement.location(),
                Optional.of(statement));
        MutableBlock after = newBlock(
                BasicBlockKind.MERGE, "while.after", statement.location(), Optional.empty());
        MutableBlock bodyEntry = newBlock(
                BasicBlockKind.STATEMENTS,
                "while.body",
                statement.body().location(),
                Optional.empty());

        connect(incoming, condition);
        addEdge(condition, bodyEntry, CfgEdgeType.TRUE_BRANCH, statement.location());
        addEdge(condition, after, CfgEdgeType.FALSE_BRANCH, statement.location());

        controlContexts.push(new ControlContext(after, condition));
        List<Pending> bodyFrontier = buildStatement(
                statement.body(),
                List.of(pending(bodyEntry, CfgEdgeType.NORMAL, statement.body().location())));
        controlContexts.pop();
        connectLoopBack(bodyFrontier, condition, statement.location(), "while.latch");
        return List.of(pending(after, CfgEdgeType.NORMAL, statement.location()));
    }

    private List<Pending> buildDoWhile(DoWhileStatement statement, List<Pending> incoming) {
        MutableBlock bodyEntry = newBlock(
                BasicBlockKind.STATEMENTS,
                "do.body",
                statement.body().location(),
                Optional.empty());
        MutableBlock condition = newBlock(
                BasicBlockKind.LOOP_HEADER,
                "do.condition",
                statement.location(),
                Optional.of(statement));
        MutableBlock after = newBlock(
                BasicBlockKind.MERGE, "do.after", statement.location(), Optional.empty());

        connect(incoming, bodyEntry);
        controlContexts.push(new ControlContext(after, condition));
        List<Pending> bodyFrontier = buildStatement(
                statement.body(),
                List.of(pending(bodyEntry, CfgEdgeType.NORMAL, statement.body().location())));
        controlContexts.pop();
        connect(bodyFrontier, condition);
        addEdge(condition, bodyEntry, CfgEdgeType.LOOP_BACK, statement.location());
        addEdge(condition, after, CfgEdgeType.FALSE_BRANCH, statement.location());
        return List.of(pending(after, CfgEdgeType.NORMAL, statement.location()));
    }

    private List<Pending> buildFor(ForStatement statement, List<Pending> incoming) {
        List<Pending> initializerFrontier = buildStatements(statement.initializers(), incoming);
        MutableBlock condition = newBlock(
                BasicBlockKind.LOOP_HEADER,
                "for.condition",
                statement.location(),
                Optional.of(statement));
        MutableBlock after = newBlock(
                BasicBlockKind.MERGE, "for.after", statement.location(), Optional.empty());
        MutableBlock bodyEntry = newBlock(
                BasicBlockKind.STATEMENTS,
                "for.body",
                statement.body().location(),
                Optional.empty());
        MutableBlock update = statement.updates().isEmpty()
                ? condition
                : createUpdateBlock(statement.updates(), statement.location());

        connect(initializerFrontier, condition);
        addEdge(condition, bodyEntry, CfgEdgeType.TRUE_BRANCH, statement.location());
        if (statement.condition().isPresent()) {
            addEdge(condition, after, CfgEdgeType.FALSE_BRANCH, statement.location());
        }

        controlContexts.push(new ControlContext(after, update));
        List<Pending> bodyFrontier = buildStatement(
                statement.body(),
                List.of(pending(bodyEntry, CfgEdgeType.NORMAL, statement.body().location())));
        controlContexts.pop();

        if (update == condition) {
            connectLoopBack(bodyFrontier, condition, statement.location(), "for.latch");
        } else {
            connect(bodyFrontier, update);
            addEdge(update, condition, CfgEdgeType.LOOP_BACK, statement.location());
        }
        return List.of(pending(after, CfgEdgeType.NORMAL, statement.location()));
    }

    private MutableBlock createUpdateBlock(List<Expression> updates, SourceLocation location) {
        MutableBlock update = newBlock(
                BasicBlockKind.LOOP_UPDATE, "for.update", location, Optional.empty());
        for (Expression expression : updates) {
            update.statements.add(new ExpressionStatement(expression, expression.location()));
        }
        return update;
    }

    private List<Pending> buildEnhancedFor(
            EnhancedForStatement statement, List<Pending> incoming) {
        MutableBlock iteration = newBlock(
                BasicBlockKind.LOOP_HEADER,
                "enhanced-for.iteration",
                statement.location(),
                Optional.of(statement));
        MutableBlock after = newBlock(
                BasicBlockKind.MERGE,
                "enhanced-for.after",
                statement.location(),
                Optional.empty());
        MutableBlock bodyEntry = newBlock(
                BasicBlockKind.STATEMENTS,
                "enhanced-for.body",
                statement.body().location(),
                Optional.empty());

        connect(incoming, iteration);
        addEdge(iteration, bodyEntry, CfgEdgeType.TRUE_BRANCH, statement.location());
        addEdge(iteration, after, CfgEdgeType.FALSE_BRANCH, statement.location());
        controlContexts.push(new ControlContext(after, iteration));
        List<Pending> bodyFrontier = buildStatement(
                statement.body(),
                List.of(pending(bodyEntry, CfgEdgeType.NORMAL, statement.body().location())));
        controlContexts.pop();
        connectLoopBack(bodyFrontier, iteration, statement.location(), "enhanced-for.latch");
        return List.of(pending(after, CfgEdgeType.NORMAL, statement.location()));
    }

    private List<Pending> buildSwitch(SwitchStatement statement, List<Pending> incoming) {
        MutableBlock selector = newBlock(
                BasicBlockKind.SWITCH_SELECTOR,
                "switch.selector",
                statement.location(),
                Optional.of(statement));
        MutableBlock after = newBlock(
                BasicBlockKind.MERGE, "switch.after", statement.location(), Optional.empty());
        connect(incoming, selector);
        controlContexts.push(new ControlContext(after, null));

        List<Pending> fallThrough = List.of();
        boolean hasDefault = false;
        for (int index = 0; index < statement.cases().size(); index++) {
            SwitchCase switchCase = statement.cases().get(index);
            MutableBlock caseEntry = newBlock(
                    BasicBlockKind.SWITCH_CASE,
                    switchCase.defaultCase() ? "switch.default" : "switch.case." + index,
                    switchCase.location(),
                    Optional.empty());
            addEdge(
                    selector,
                    caseEntry,
                    switchCase.defaultCase()
                            ? CfgEdgeType.SWITCH_DEFAULT
                            : CfgEdgeType.SWITCH_CASE,
                    switchCase.location());
            hasDefault |= switchCase.defaultCase();
            connect(fallThrough, caseEntry);

            List<Pending> caseFrontier = buildStatements(
                    switchCase.statements(),
                    List.of(pending(caseEntry, CfgEdgeType.NORMAL, switchCase.location())));
            if (switchCase.kind() == SwitchCaseKind.ARROW_RULE) {
                unsupported.add(new UnsupportedControlFlow(
                        "switch arrow rule",
                        "Arrow-rule value/yield semantics are not fully modeled; fall-through is disabled",
                        switchCase.location()));
                connect(caseFrontier, after);
                fallThrough = List.of();
            } else {
                fallThrough = caseFrontier;
            }
        }
        controlContexts.pop();
        connect(fallThrough, after);
        if (!hasDefault) {
            addEdge(selector, after, CfgEdgeType.SWITCH_DEFAULT, statement.location());
        }
        return List.of(pending(after, CfgEdgeType.NORMAL, statement.location()));
    }

    private void connectLoopBack(
            List<Pending> frontier,
            MutableBlock target,
            SourceLocation location,
            String latchLabel) {
        if (frontier.isEmpty()) {
            return;
        }
        if (frontier.size() == 1 && frontier.getFirst().type == CfgEdgeType.NORMAL) {
            addEdge(frontier.getFirst().source, target, CfgEdgeType.LOOP_BACK, location);
            return;
        }
        MutableBlock latch = newBlock(
                BasicBlockKind.MERGE, latchLabel, location, Optional.empty());
        connect(frontier, latch);
        addEdge(latch, target, CfgEdgeType.LOOP_BACK, location);
    }

    private Optional<MutableBlock> nearestBreakTarget() {
        return controlContexts.stream().map(ControlContext::breakTarget).findFirst();
    }

    private Optional<MutableBlock> nearestContinueTarget() {
        return controlContexts.stream()
                .map(ControlContext::continueTarget)
                .filter(Objects::nonNull)
                .findFirst();
    }

    private MutableBlock newBlock(
            BasicBlockKind kind,
            String label,
            SourceLocation location,
            Optional<Statement> controlStatement) {
        MutableBlock block = new MutableBlock(
                nextBlockId++, kind, label, location, controlStatement);
        blocks.add(block);
        return block;
    }

    private Pending pending(
            MutableBlock source, CfgEdgeType type, SourceLocation location) {
        return new Pending(source, type, location);
    }

    private void connect(List<Pending> pendingEdges, MutableBlock target) {
        for (Pending pending : pendingEdges) {
            if (pending.source != target) {
                addEdge(pending.source, target, pending.type, pending.location);
            }
        }
    }

    private void addEdge(
            MutableBlock source,
            MutableBlock target,
            CfgEdgeType type,
            SourceLocation location) {
        boolean duplicate = edges.stream().anyMatch(edge ->
                edge.source == source && edge.target == target && edge.type == type);
        if (!duplicate) {
            edges.add(new MutableEdge(source, target, type, location));
        }
    }

    private ControlFlowGraph freeze() {
        Map<Integer, BasicBlock> immutableBlocks = new LinkedHashMap<>();
        for (MutableBlock block : blocks) {
            immutableBlocks.put(
                    block.id,
                    new BasicBlock(
                            block.id,
                            block.kind,
                            block.label,
                            block.statements,
                            block.controlStatement,
                            block.location));
        }
        List<CfgEdge> immutableEdges = edges.stream()
                .map(edge -> new CfgEdge(
                        immutableBlocks.get(edge.source.id),
                        immutableBlocks.get(edge.target.id),
                        edge.type,
                        edge.location))
                .toList();
        return new ControlFlowGraph(
                method,
                immutableBlocks.get(entry.id),
                immutableBlocks.get(exit.id),
                List.copyOf(immutableBlocks.values()),
                immutableEdges,
                unsupported);
    }

    private static final class MutableBlock {
        private final int id;
        private final BasicBlockKind kind;
        private final String label;
        private final List<Statement> statements = new ArrayList<>();
        private final Optional<Statement> controlStatement;
        private final SourceLocation location;
        private boolean terminated;

        private MutableBlock(
                int id,
                BasicBlockKind kind,
                String label,
                SourceLocation location,
                Optional<Statement> controlStatement) {
            this.id = id;
            this.kind = kind;
            this.label = label;
            this.location = location;
            this.controlStatement = controlStatement;
        }

        private boolean canAppend() {
            return !terminated
                    && switch (kind) {
                        case STATEMENTS, LOOP_UPDATE, SWITCH_CASE, MERGE -> true;
                        default -> false;
                    };
        }
    }

    private record MutableEdge(
            MutableBlock source,
            MutableBlock target,
            CfgEdgeType type,
            SourceLocation location) {}

    private record Pending(
            MutableBlock source, CfgEdgeType type, SourceLocation location) {}

    private record ControlContext(
            MutableBlock breakTarget, MutableBlock continueTarget) {}
}

