package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.expression.AssignmentExpression;
import com.totalsecurity.sast.ir.expression.BinaryExpression;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.ObjectCreationExpression;
import com.totalsecurity.sast.ir.expression.ParenthesizedExpression;
import com.totalsecurity.sast.ir.expression.UnknownExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
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
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Intraprocedural, flow-sensitive reaching-definitions analysis over the project IR and CFG. */
public final class ReachingDefinitionsAnalysis {
    public DataFlowResult analyze(ControlFlowGraph graph) {
        Objects.requireNonNull(graph, "graph");
        LexicalIndex lexicalIndex = LexicalIndex.build(graph.method());
        AnalysisContext context = new AnalysisContext(graph, lexicalIndex);
        Set<BasicBlock> reachable = graph.reachableBlocks();

        LinkedHashMap<BasicBlock, DataFlowState> inStates = new LinkedHashMap<>();
        LinkedHashMap<BasicBlock, DataFlowState> outStates = new LinkedHashMap<>();
        LinkedHashMap<BasicBlock, Integer> evaluationCounts = new LinkedHashMap<>();
        ArrayDeque<BasicBlock> worklist = new ArrayDeque<>();
        LinkedHashSet<BasicBlock> queued = new LinkedHashSet<>();

        for (BasicBlock block : graph.blocks()) {
            if (reachable.contains(block)) {
                inStates.put(block, DataFlowState.empty());
                outStates.put(block, DataFlowState.empty());
                worklist.addLast(block);
                queued.add(block);
            }
        }

        while (!worklist.isEmpty()) {
            BasicBlock block = worklist.removeFirst();
            queued.remove(block);
            evaluationCounts.merge(block, 1, Integer::sum);

            DataFlowState newIn = block.equals(graph.entry())
                    ? DataFlowState.empty()
                    : joinPredecessors(graph, block, reachable, outStates);
            DataFlowState newOut = transferBlock(block, newIn, context);
            boolean changed = !newIn.equals(inStates.get(block))
                    || !newOut.equals(outStates.get(block));
            inStates.put(block, newIn);
            outStates.put(block, newOut);

            if (changed) {
                for (BasicBlock successor : graph.successors(block)) {
                    if (reachable.contains(successor) && queued.add(successor)) {
                        worklist.addLast(successor);
                    }
                }
            }
        }

        return context.toResult(inStates, outStates, evaluationCounts);
    }

    private DataFlowState joinPredecessors(
            ControlFlowGraph graph,
            BasicBlock block,
            Set<BasicBlock> reachable,
            Map<BasicBlock, DataFlowState> outStates) {
        List<DataFlowState> predecessorStates = graph.predecessors(block).stream()
                .filter(reachable::contains)
                .map(outStates::get)
                .filter(Objects::nonNull)
                .toList();
        return DataFlowState.join(predecessorStates);
    }

    private DataFlowState transferBlock(
            BasicBlock block, DataFlowState input, AnalysisContext context) {
        DataFlowState state = input;
        if (block.equals(context.graph.entry())) {
            for (Definition parameterDefinition : context.parameterDefinitions) {
                state = state.redefine(parameterDefinition);
            }
        }

        if (block.controlStatement().isPresent()) {
            Statement control = block.controlStatement().orElseThrow();
            context.statementBeforeStates.put(control, state);
            state = transferControlExpression(control, block, state, context);
        }

        for (Statement statement : block.statements()) {
            context.statementBeforeStates.put(statement, state);
            state = transferStatement(statement, block, state, context);
        }
        return state;
    }

    private DataFlowState transferControlExpression(
            Statement statement,
            BasicBlock block,
            DataFlowState state,
            AnalysisContext context) {
        return switch (statement) {
            case IfStatement conditional ->
                    transferExpression(conditional.condition(), statement, block, state, context);
            case WhileStatement loop ->
                    transferExpression(loop.condition(), statement, block, state, context);
            case DoWhileStatement loop ->
                    transferExpression(loop.condition(), statement, block, state, context);
            case ForStatement loop -> loop.condition()
                    .map(condition -> transferExpression(condition, statement, block, state, context))
                    .orElse(state);
            case EnhancedForStatement loop -> {
                DataFlowState afterIterable =
                        transferExpression(loop.iterable(), statement, block, state, context);
                context.unsupported.add(new UnsupportedDataFlow(
                        "enhanced-for variable",
                        "The CFG does not expose the true-edge element assignment as a separate operation",
                        loop.variable().location()));
                yield afterIterable;
            }
            case SwitchStatement selection ->
                    transferExpression(selection.selector(), statement, block, state, context);
            default -> state;
        };
    }

    private DataFlowState transferStatement(
            Statement statement,
            BasicBlock block,
            DataFlowState state,
            AnalysisContext context) {
        return switch (statement) {
            case VariableDeclarationStatement declaration ->
                    transferDeclaration(declaration, block, state, context);
            case ExpressionStatement expression ->
                    transferExpression(expression.expression(), statement, block, state, context);
            case ReturnStatement returned -> returned.expression()
                    .map(expression -> transferExpression(expression, statement, block, state, context))
                    .orElse(state);
            case ThrowStatement thrown ->
                    transferExpression(thrown.expression(), statement, block, state, context);
            case UnknownStatement unknown -> {
                context.unsupported.add(new UnsupportedDataFlow(
                        unknown.syntaxKind(),
                        "Unknown statement source is not interpreted for definitions or uses",
                        unknown.location()));
                yield state;
            }
            case BlockStatement blockStatement -> {
                DataFlowState nested = state;
                for (Statement child : blockStatement.statements()) {
                    context.statementBeforeStates.put(child, nested);
                    nested = transferStatement(child, block, nested, context);
                }
                yield nested;
            }
            case IfStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case WhileStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case DoWhileStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case ForStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case EnhancedForStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case SwitchStatement ignored ->
                    transferControlExpression(statement, block, state, context);
            case BreakStatement ignored -> state;
            case ContinueStatement ignored -> state;
        };
    }

    private DataFlowState transferDeclaration(
            VariableDeclarationStatement declaration,
            BasicBlock block,
            DataFlowState input,
            AnalysisContext context) {
        DataFlowState state = input;
        for (VariableInfo variable : declaration.variables()) {
            if (variable.initializer().isEmpty()) {
                continue;
            }
            Expression initializer = variable.initializer().orElseThrow();
            state = transferExpression(initializer, declaration, block, state, context);
            Optional<VariableSymbol> symbol = context.lexicalIndex.symbol(variable);
            if (symbol.isEmpty()) {
                context.unsupported.add(new UnsupportedDataFlow(
                        "variable declaration",
                        "No lexical symbol was established for the declaration",
                        variable.location()));
                continue;
            }
            Definition definition = context.initializerDefinitions.computeIfAbsent(
                    variable,
                    ignored -> context.newDefinition(
                            symbol.orElseThrow(),
                            DefinitionKind.VARIABLE_INITIALIZER,
                            Optional.of(initializer),
                            Optional.empty(),
                            variable.location(),
                            Optional.of(declaration)));
            state = state.redefine(definition);
        }
        return state;
    }

    private DataFlowState transferExpression(
            Expression expression,
            Statement statement,
            BasicBlock block,
            DataFlowState state,
            AnalysisContext context) {
        return switch (expression) {
            case VariableReference reference -> {
                recordUse(reference, statement, block, state, context);
                yield state;
            }
            case Literal ignored -> state;
            case BinaryExpression binary -> {
                DataFlowState afterLeft =
                        transferExpression(binary.left(), statement, block, state, context);
                yield transferExpression(binary.right(), statement, block, afterLeft, context);
            }
            case AssignmentExpression assignment ->
                    transferAssignment(assignment, statement, block, state, context);
            case MethodCallExpression call -> {
                DataFlowState current = state;
                if (call.call().receiver().isPresent()) {
                    current = transferExpression(
                            call.call().receiver().orElseThrow(), statement, block, current, context);
                }
                for (Expression argument : call.call().arguments()) {
                    current = transferExpression(argument, statement, block, current, context);
                }
                yield current;
            }
            case ObjectCreationExpression creation -> {
                DataFlowState current = state;
                for (Expression argument : creation.arguments()) {
                    current = transferExpression(argument, statement, block, current, context);
                }
                yield current;
            }
            case FieldAccessExpression field ->
                    transferExpression(field.target(), statement, block, state, context);
            case ParenthesizedExpression parenthesized -> transferExpression(
                    parenthesized.expression(), statement, block, state, context);
            case UnknownExpression unknown -> {
                context.unsupported.add(new UnsupportedDataFlow(
                        unknown.syntaxKind(),
                        "Unknown expression source is not interpreted for definitions or uses",
                        unknown.location()));
                yield state;
            }
        };
    }

    private DataFlowState transferAssignment(
            AssignmentExpression expression,
            Statement statement,
            BasicBlock block,
            DataFlowState input,
            AnalysisContext context) {
        AssignmentInfo assignment = expression.assignment();
        boolean compound = !assignment.operator().equals("=");
        DataFlowState state = transferAssignmentTarget(
                assignment.left(), compound, statement, block, input, context);
        state = transferExpression(assignment.right(), statement, block, state, context);

        Optional<VariableSymbol> target = context.lexicalIndex.assignmentTarget(expression);
        if (target.isEmpty()) {
            context.unsupported.add(new UnsupportedDataFlow(
                    "assignment target",
                    "Only lexically resolved parameter/local variable assignments generate definitions",
                    assignment.left().location()));
            return state;
        }
        if (compound) {
            context.unsupported.add(new UnsupportedDataFlow(
                    "compound assignment " + assignment.operator(),
                    "The prior local value is modeled as a use, but operator value semantics are not interpreted",
                    assignment.location()));
        }
        Definition definition = context.assignmentDefinitions.computeIfAbsent(
                expression,
                ignored -> context.newDefinition(
                        target.orElseThrow(),
                        DefinitionKind.ASSIGNMENT,
                        Optional.of(assignment.right()),
                        Optional.of(assignment.operator()),
                        assignment.location(),
                        Optional.of(statement)));
        return state.redefine(definition);
    }

    private DataFlowState transferAssignmentTarget(
            Expression target,
            boolean readPriorValue,
            Statement statement,
            BasicBlock block,
            DataFlowState state,
            AnalysisContext context) {
        if (target instanceof VariableReference reference) {
            if (readPriorValue) {
                recordUse(reference, statement, block, state, context);
            } else if (context.lexicalIndex.symbol(reference).isEmpty()) {
                context.unresolved.add(new UnresolvedReference(
                        reference, "Assignment target is not a lexically visible parameter/local variable"));
            }
            return state;
        }
        if (target instanceof ParenthesizedExpression parenthesized) {
            return transferAssignmentTarget(
                    parenthesized.expression(), readPriorValue, statement, block, state, context);
        }
        if (target instanceof FieldAccessExpression field) {
            return transferExpression(field.target(), statement, block, state, context);
        }
        context.unsupported.add(new UnsupportedDataFlow(
                "assignment target",
                "Unsupported assignment target shape is not interpreted",
                target.location()));
        return state;
    }

    private void recordUse(
            VariableReference reference,
            Statement statement,
            BasicBlock block,
            DataFlowState state,
            AnalysisContext context) {
        Optional<VariableSymbol> symbol = context.lexicalIndex.symbol(reference);
        if (symbol.isEmpty()) {
            context.unresolved.add(new UnresolvedReference(
                    reference, "No lexically visible parameter/local declaration"));
            return;
        }
        UseSite useSite = new UseSite(reference, symbol.orElseThrow(), block, statement);
        context.useSites.put(reference, useSite);
        context.reachingDefinitionsByUse.put(
                reference, state.definitionsOf(symbol.orElseThrow()));
    }

    private static final class AnalysisContext {
        private final ControlFlowGraph graph;
        private final LexicalIndex lexicalIndex;
        private final List<Definition> parameterDefinitions = new ArrayList<>();
        private final IdentityHashMap<VariableInfo, Definition> initializerDefinitions =
                new IdentityHashMap<>();
        private final IdentityHashMap<AssignmentExpression, Definition> assignmentDefinitions =
                new IdentityHashMap<>();
        private final List<Definition> definitions = new ArrayList<>();
        private final LinkedHashMap<Statement, DataFlowState> statementBeforeStates =
                new LinkedHashMap<>();
        private final LinkedHashMap<VariableReference, UseSite> useSites = new LinkedHashMap<>();
        private final LinkedHashMap<VariableReference, Set<Definition>> reachingDefinitionsByUse =
                new LinkedHashMap<>();
        private final LinkedHashSet<UnresolvedReference> unresolved = new LinkedHashSet<>();
        private final LinkedHashSet<UnsupportedDataFlow> unsupported = new LinkedHashSet<>();
        private int nextDefinitionId;

        private AnalysisContext(ControlFlowGraph graph, LexicalIndex lexicalIndex) {
            this.graph = graph;
            this.lexicalIndex = lexicalIndex;
            for (ParameterInfo parameter : graph.method().parameters()) {
                lexicalIndex.symbol(parameter).ifPresent(symbol -> parameterDefinitions.add(newDefinition(
                        symbol,
                        DefinitionKind.PARAMETER,
                        Optional.empty(),
                        Optional.empty(),
                        parameter.location(),
                        Optional.empty())));
            }
        }

        private Definition newDefinition(
                VariableSymbol variable,
                DefinitionKind kind,
                Optional<Expression> assignedExpression,
                Optional<String> assignmentOperator,
                com.totalsecurity.sast.ir.SourceLocation location,
                Optional<Statement> statement) {
            Definition definition = new Definition(
                    nextDefinitionId++,
                    variable,
                    kind,
                    assignedExpression,
                    assignmentOperator,
                    location,
                    statement);
            definitions.add(definition);
            return definition;
        }

        private DataFlowResult toResult(
                Map<BasicBlock, DataFlowState> inStates,
                Map<BasicBlock, DataFlowState> outStates,
                Map<BasicBlock, Integer> evaluationCounts) {
            return new DataFlowResult(
                    graph,
                    inStates,
                    outStates,
                    statementBeforeStates,
                    useSites,
                    reachingDefinitionsByUse,
                    lexicalIndex.resolvedReferences(),
                    lexicalIndex.symbols(),
                    definitions.stream().sorted(java.util.Comparator.comparingInt(Definition::id)).toList(),
                    List.copyOf(unresolved),
                    List.copyOf(unsupported),
                    evaluationCounts);
        }
    }

    /** Establishes only declarations and references resolvable from the ordered lexical IR. */
    private static final class LexicalIndex {
        private final Deque<Map<String, VariableSymbol>> scopes = new ArrayDeque<>();
        private final IdentityHashMap<ParameterInfo, VariableSymbol> parameterSymbols =
                new IdentityHashMap<>();
        private final IdentityHashMap<VariableInfo, VariableSymbol> variableSymbols =
                new IdentityHashMap<>();
        private final IdentityHashMap<VariableReference, VariableSymbol> referenceSymbols =
                new IdentityHashMap<>();
        private final IdentityHashMap<AssignmentExpression, VariableSymbol> assignmentTargets =
                new IdentityHashMap<>();
        private final List<VariableSymbol> symbols = new ArrayList<>();
        private int nextSymbolId;

        private static LexicalIndex build(MethodInfo method) {
            LexicalIndex index = new LexicalIndex();
            index.scopes.push(new LinkedHashMap<>());
            for (ParameterInfo parameter : method.parameters()) {
                VariableSymbol symbol = index.newSymbol(
                        parameter.name(),
                        VariableSymbolKind.PARAMETER,
                        parameter.type(),
                        parameter.location());
                index.parameterSymbols.put(parameter, symbol);
                index.scopes.peek().put(parameter.name(), symbol);
            }
            method.body().ifPresent(index::walkBlock);
            index.scopes.pop();
            return index;
        }

        private VariableSymbol newSymbol(
                String name,
                VariableSymbolKind kind,
                String declaredType,
                com.totalsecurity.sast.ir.SourceLocation location) {
            VariableSymbol symbol =
                    new VariableSymbol(nextSymbolId++, name, kind, declaredType, location);
            symbols.add(symbol);
            return symbol;
        }

        private void walkBlock(BlockStatement block) {
            scopes.push(new LinkedHashMap<>());
            block.statements().forEach(this::walkStatement);
            scopes.pop();
        }

        private void walkStatement(Statement statement) {
            switch (statement) {
                case BlockStatement block -> walkBlock(block);
                case VariableDeclarationStatement declaration ->
                        declaration.variables().forEach(this::walkVariableDeclaration);
                case ExpressionStatement expression -> walkExpression(expression.expression());
                case ReturnStatement returned -> returned.expression().ifPresent(this::walkExpression);
                case ThrowStatement thrown -> walkExpression(thrown.expression());
                case IfStatement conditional -> {
                    walkExpression(conditional.condition());
                    walkStatement(conditional.thenBranch());
                    conditional.elseBranch().ifPresent(this::walkStatement);
                }
                case WhileStatement loop -> {
                    walkExpression(loop.condition());
                    walkStatement(loop.body());
                }
                case DoWhileStatement loop -> {
                    walkStatement(loop.body());
                    walkExpression(loop.condition());
                }
                case ForStatement loop -> walkFor(loop);
                case EnhancedForStatement loop -> walkEnhancedFor(loop);
                case SwitchStatement selection -> walkSwitch(selection);
                case BreakStatement ignored -> {
                    // No variable semantics.
                }
                case ContinueStatement ignored -> {
                    // No variable semantics.
                }
                case UnknownStatement ignored -> {
                    // No safe variable semantics are inferred from these statements.
                }
            }
        }

        private void walkVariableDeclaration(VariableInfo variable) {
            variable.initializer().ifPresent(this::walkExpression);
            VariableSymbol symbol = newSymbol(
                    variable.name(),
                    VariableSymbolKind.LOCAL,
                    variable.type(),
                    variable.location());
            variableSymbols.put(variable, symbol);
            scopes.peek().put(variable.name(), symbol);
        }

        private void walkFor(ForStatement loop) {
            scopes.push(new LinkedHashMap<>());
            loop.initializers().forEach(this::walkStatement);
            loop.condition().ifPresent(this::walkExpression);
            walkStatement(loop.body());
            loop.updates().forEach(this::walkExpression);
            scopes.pop();
        }

        private void walkEnhancedFor(EnhancedForStatement loop) {
            walkExpression(loop.iterable());
            scopes.push(new LinkedHashMap<>());
            VariableInfo variable = loop.variable();
            VariableSymbol symbol = newSymbol(
                    variable.name(),
                    VariableSymbolKind.LOCAL,
                    variable.type(),
                    variable.location());
            variableSymbols.put(variable, symbol);
            scopes.peek().put(variable.name(), symbol);
            walkStatement(loop.body());
            scopes.pop();
        }

        private void walkSwitch(SwitchStatement selection) {
            walkExpression(selection.selector());
            scopes.push(new LinkedHashMap<>());
            selection.cases().forEach(switchCase -> {
                switchCase.labels().forEach(this::walkExpression);
                switchCase.statements().forEach(this::walkStatement);
            });
            scopes.pop();
        }

        private void walkExpression(Expression expression) {
            switch (expression) {
                case VariableReference reference -> bindReference(reference);
                case Literal ignored -> {
                    // Literal has no references.
                }
                case UnknownExpression ignored -> {
                    // Unknown source is intentionally opaque.
                }
                case BinaryExpression binary -> {
                    walkExpression(binary.left());
                    walkExpression(binary.right());
                }
                case AssignmentExpression assignment -> walkAssignment(assignment);
                case MethodCallExpression call -> {
                    call.call().receiver().ifPresent(this::walkExpression);
                    call.call().arguments().forEach(this::walkExpression);
                }
                case ObjectCreationExpression creation ->
                        creation.arguments().forEach(this::walkExpression);
                case FieldAccessExpression field -> walkExpression(field.target());
                case ParenthesizedExpression parenthesized ->
                        walkExpression(parenthesized.expression());
            }
        }

        private void walkAssignment(AssignmentExpression expression) {
            Expression left = expression.assignment().left();
            Optional<VariableReference> localTarget = localTarget(left);
            if (localTarget.isPresent()) {
                VariableReference reference = localTarget.orElseThrow();
                bindReference(reference);
                symbol(reference).ifPresent(symbol -> assignmentTargets.put(expression, symbol));
            } else {
                walkExpression(left);
            }
            walkExpression(expression.assignment().right());
        }

        private Optional<VariableReference> localTarget(Expression expression) {
            if (expression instanceof VariableReference reference) {
                return Optional.of(reference);
            }
            if (expression instanceof ParenthesizedExpression parenthesized) {
                return localTarget(parenthesized.expression());
            }
            return Optional.empty();
        }

        private void bindReference(VariableReference reference) {
            resolve(reference.name()).ifPresent(symbol -> referenceSymbols.put(reference, symbol));
        }

        private Optional<VariableSymbol> resolve(String name) {
            for (Map<String, VariableSymbol> scope : scopes) {
                VariableSymbol symbol = scope.get(name);
                if (symbol != null) {
                    return Optional.of(symbol);
                }
            }
            return Optional.empty();
        }

        private Optional<VariableSymbol> symbol(ParameterInfo parameter) {
            return Optional.ofNullable(parameterSymbols.get(parameter));
        }

        private Optional<VariableSymbol> symbol(VariableInfo variable) {
            return Optional.ofNullable(variableSymbols.get(variable));
        }

        private Optional<VariableSymbol> symbol(VariableReference reference) {
            return Optional.ofNullable(referenceSymbols.get(reference));
        }

        private Optional<VariableSymbol> assignmentTarget(AssignmentExpression expression) {
            return Optional.ofNullable(assignmentTargets.get(expression));
        }

        private List<VariableSymbol> symbols() {
            return List.copyOf(symbols);
        }

        private Map<VariableReference, VariableSymbol> resolvedReferences() {
            LinkedHashMap<VariableReference, VariableSymbol> resolved = new LinkedHashMap<>();
            referenceSymbols.forEach(resolved::put);
            return Collections.unmodifiableMap(resolved);
        }
    }
}
