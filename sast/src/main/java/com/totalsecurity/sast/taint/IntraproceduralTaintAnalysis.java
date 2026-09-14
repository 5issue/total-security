package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.ir.AssignmentInfo;
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
import com.totalsecurity.sast.ir.statement.DoWhileStatement;
import com.totalsecurity.sast.ir.statement.EnhancedForStatement;
import com.totalsecurity.sast.ir.statement.ExpressionStatement;
import com.totalsecurity.sast.ir.statement.ForStatement;
import com.totalsecurity.sast.ir.statement.IfStatement;
import com.totalsecurity.sast.ir.statement.ReturnStatement;
import com.totalsecurity.sast.ir.statement.Statement;
import com.totalsecurity.sast.ir.statement.SwitchStatement;
import com.totalsecurity.sast.ir.statement.ThrowStatement;
import com.totalsecurity.sast.ir.statement.VariableDeclarationStatement;
import com.totalsecurity.sast.ir.statement.WhileStatement;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Intraprocedural may-taint propagation over stable STEP 4 definitions and use sites. */
public final class IntraproceduralTaintAnalysis {
    public TaintAnalysisResult analyze(DataFlowResult dataFlow, Collection<? extends TaintSeed> seeds) {
        Objects.requireNonNull(dataFlow, "dataFlow");
        Objects.requireNonNull(seeds, "seeds");
        ExpressionIndex expressions = ExpressionIndex.build(dataFlow);
        AnalysisContext context = new AnalysisContext(dataFlow, expressions, seeds);
        Map<Definition, Set<Definition>> dependents = buildDependents(dataFlow);

        ArrayDeque<Definition> worklist = new ArrayDeque<>();
        LinkedHashSet<Definition> queued = new LinkedHashSet<>();
        List<Definition> definitions = dataFlow.definitions();
        for (int index = definitions.size() - 1; index >= 0; index--) {
            Definition definition = definitions.get(index);
            context.definitionTaints.put(definition, TaintValue.clean());
            worklist.addLast(definition);
            queued.add(definition);
        }

        while (!worklist.isEmpty()) {
            Definition definition = worklist.removeFirst();
            queued.remove(definition);
            context.evaluationCounts.merge(definition, 1, Integer::sum);
            TaintValue previous = context.definitionTaints.get(definition);
            TaintValue updated = context.evaluateDefinition(definition);
            context.definitionTaints.put(definition, updated);
            if (!updated.equals(previous)) {
                for (Definition dependent : dependents.getOrDefault(definition, Set.of())) {
                    if (queued.add(dependent)) {
                        worklist.addLast(dependent);
                    }
                }
            }
        }

        for (Expression expression : expressions.expressions()) {
            context.evaluateExpression(expression);
        }
        return context.toResult();
    }

    private Map<Definition, Set<Definition>> buildDependents(DataFlowResult dataFlow) {
        LinkedHashMap<Definition, Set<Definition>> dependents = new LinkedHashMap<>();
        for (Definition dependent : dataFlow.definitions()) {
            if (dependent.assignedExpression().isEmpty()) {
                continue;
            }
            LinkedHashSet<VariableReference> references = new LinkedHashSet<>();
            collectReferences(dependent.assignedExpression().orElseThrow(), references);
            for (VariableReference reference : references) {
                for (Definition upstream : dataFlow.reachingDefinitions(reference)) {
                    dependents.computeIfAbsent(upstream, ignored -> new LinkedHashSet<>())
                            .add(dependent);
                }
            }
        }
        return dependents;
    }

    private void collectReferences(Expression expression, Set<VariableReference> references) {
        switch (expression) {
            case VariableReference reference -> references.add(reference);
            case Literal ignored -> {
                // Literal has no variable references.
            }
            case UnknownExpression ignored -> {
                // Unknown source text is intentionally opaque.
            }
            case BinaryExpression binary -> {
                collectReferences(binary.left(), references);
                collectReferences(binary.right(), references);
            }
            case AssignmentExpression assignment -> {
                if (!assignment.assignment().operator().equals("=")) {
                    collectReferences(assignment.assignment().left(), references);
                } else if (assignment.assignment().left() instanceof FieldAccessExpression field) {
                    collectReferences(field.target(), references);
                }
                collectReferences(assignment.assignment().right(), references);
            }
            case MethodCallExpression call -> {
                call.call().receiver().ifPresent(receiver -> collectReferences(receiver, references));
                call.call().arguments().forEach(argument -> collectReferences(argument, references));
            }
            case ObjectCreationExpression creation ->
                    creation.arguments().forEach(argument -> collectReferences(argument, references));
            case FieldAccessExpression field -> collectReferences(field.target(), references);
            case ParenthesizedExpression parenthesized ->
                    collectReferences(parenthesized.expression(), references);
        }
    }

    private static final class AnalysisContext {
        private final DataFlowResult dataFlow;
        private final ExpressionIndex expressions;
        private final Set<TaintSeed> seeds;
        private final Map<Definition, List<TaintSeed>> definitionSeeds = new LinkedHashMap<>();
        private final IdentityHashMap<Expression, List<TaintSeed>> expressionSeeds =
                new IdentityHashMap<>();
        private final LinkedHashMap<Definition, TaintValue> definitionTaints =
                new LinkedHashMap<>();
        private final LinkedHashMap<Expression, TaintValue> expressionTaints =
                new LinkedHashMap<>();
        private final LinkedHashMap<UseSite, TaintValue> useSiteTaints =
                new LinkedHashMap<>();
        private final LinkedHashMap<MethodCallExpression, MethodCallTaint> methodCalls =
                new LinkedHashMap<>();
        private final LinkedHashSet<UnsupportedTaint> unsupported = new LinkedHashSet<>();
        private final LinkedHashSet<TaintTraceStep> traceSteps = new LinkedHashSet<>();
        private final LinkedHashSet<TaintTraceEdge> traceEdges = new LinkedHashSet<>();
        private final Map<TaintSeed, TaintTraceStep> seedSteps = new LinkedHashMap<>();
        private final IdentityHashMap<Definition, TaintTraceStep> definitionSteps =
                new IdentityHashMap<>();
        private final Map<UseSite, TaintTraceStep> useSteps = new LinkedHashMap<>();
        private final IdentityHashMap<Expression, TaintTraceStep> expressionSteps =
                new IdentityHashMap<>();
        private final LinkedHashMap<Definition, Integer> evaluationCounts =
                new LinkedHashMap<>();
        private int nextTraceStepId;

        private AnalysisContext(
                DataFlowResult dataFlow,
                ExpressionIndex expressions,
                Collection<? extends TaintSeed> seeds) {
            this.dataFlow = dataFlow;
            this.expressions = expressions;
            this.seeds = Collections.unmodifiableSet(new LinkedHashSet<>(seeds));
            validateAndIndexSeeds();
        }

        private void validateAndIndexSeeds() {
            for (TaintSeed seed : seeds) {
                Objects.requireNonNull(seed, "seed");
                if (seed instanceof DefinitionTaintSeed definitionSeed) {
                    if (!dataFlow.definitions().contains(definitionSeed.definition())) {
                        throw new IllegalArgumentException(
                                "Definition seed is not part of the reachable DataFlowResult");
                    }
                    definitionSeeds
                            .computeIfAbsent(definitionSeed.definition(), ignored -> new ArrayList<>())
                            .add(seed);
                } else if (seed instanceof ExpressionTaintSeed expressionSeed) {
                    if (!expressions.contains(expressionSeed.expression())) {
                        throw new IllegalArgumentException(
                                "Expression seed is not part of the reachable CFG");
                    }
                    expressionSeeds
                            .computeIfAbsent(expressionSeed.expression(), ignored -> new ArrayList<>())
                            .add(seed);
                }
            }
        }

        private TaintValue evaluateDefinition(Definition definition) {
            TaintValue expressionValue = definition.assignedExpression()
                    .map(this::evaluateExpression)
                    .orElseGet(TaintValue::clean);
            TaintValue result = expressionValue;
            for (TaintSeed seed : definitionSeeds.getOrDefault(definition, List.of())) {
                result = result.join(TaintValue.tainted(seed));
                addEdge(step(seed), step(definition));
            }
            if (expressionValue.state() == TaintState.TAINTED
                    && definition.assignedExpression().isPresent()) {
                addEdge(terminalStep(definition.assignedExpression().orElseThrow()), step(definition));
            }
            return result;
        }

        private TaintValue evaluateExpression(Expression expression) {
            TaintValue value = switch (expression) {
                case VariableReference reference -> evaluateReference(reference);
                case Literal ignored -> TaintValue.clean();
                case BinaryExpression binary -> evaluateJoinedExpression(
                        expression, List.of(binary.left(), binary.right()));
                case AssignmentExpression assignment -> evaluateAssignment(assignment);
                case MethodCallExpression call -> evaluateMethodCall(call);
                case ObjectCreationExpression creation -> evaluateObjectCreation(creation);
                case FieldAccessExpression field -> evaluateFieldAccess(field);
                case ParenthesizedExpression parenthesized -> evaluateForwardingExpression(
                        expression, parenthesized.expression());
                case UnknownExpression unknown -> {
                    unsupported.add(new UnsupportedTaint(
                            unknown.syntaxKind(),
                            "Unknown expression source is not inspected or interpreted for taint",
                            unknown.location()));
                    yield TaintValue.unknown();
                }
            };
            value = applyExpressionSeeds(expression, value);
            expressionTaints.put(expression, value);
            if (expression instanceof MethodCallExpression call) {
                MethodCallTaint parts = methodCalls.get(call);
                methodCalls.put(call, new MethodCallTaint(
                        call, parts.receiver(), parts.arguments(), value));
            }
            return value;
        }

        private TaintValue evaluateReference(VariableReference reference) {
            Optional<UseSite> useSite = dataFlow.useSite(reference);
            if (useSite.isEmpty()) {
                unsupported.add(new UnsupportedTaint(
                        "unresolved variable reference",
                        "No resolved reachable use site is available",
                        reference.location()));
                return TaintValue.unknown();
            }
            List<TaintValue> reaching = dataFlow.reachingDefinitions(reference).stream()
                    .map(definitionTaints::get)
                    .filter(Objects::nonNull)
                    .toList();
            TaintValue value = TaintValue.join(reaching);
            UseSite use = useSite.orElseThrow();
            useSiteTaints.put(use, value);
            if (value.state() == TaintState.TAINTED) {
                for (Definition definition : dataFlow.reachingDefinitions(reference)) {
                    TaintValue definitionValue = definitionTaints.get(definition);
                    if (definitionValue != null && definitionValue.state() == TaintState.TAINTED) {
                        addEdge(step(definition), step(use));
                    }
                }
            }
            return value;
        }

        private TaintValue evaluateJoinedExpression(
                Expression expression, List<Expression> children) {
            List<TaintValue> childValues = children.stream().map(this::evaluateExpression).toList();
            TaintValue value = TaintValue.join(childValues);
            connectTaintedChildren(children, childValues, expression, value);
            return value;
        }

        private TaintValue evaluateForwardingExpression(Expression outer, Expression inner) {
            TaintValue value = evaluateExpression(inner);
            if (value.state() == TaintState.TAINTED) {
                addEdge(terminalStep(inner), step(outer));
            }
            return value;
        }

        private TaintValue evaluateAssignment(AssignmentExpression expression) {
            AssignmentInfo assignment = expression.assignment();
            if (assignment.operator().equals("=")) {
                return evaluateForwardingExpression(expression, assignment.right());
            }
            TaintValue value = evaluateJoinedExpression(
                    expression, List.of(assignment.left(), assignment.right()));
            unsupported.add(new UnsupportedTaint(
                    "compound assignment " + assignment.operator(),
                    "May-taint joins the prior target and RHS, but operator value semantics are not modeled",
                    assignment.location()));
            return value;
        }

        private TaintValue evaluateMethodCall(MethodCallExpression call) {
            Optional<TaintValue> receiver = call.call().receiver().map(this::evaluateExpression);
            List<TaintValue> arguments =
                    call.call().arguments().stream().map(this::evaluateExpression).toList();
            TaintValue result = TaintValue.unknown();
            if (!expressionSeeds.containsKey(call)) {
                unsupported.add(new UnsupportedTaint(
                        "method call result",
                        "Return taint is UNKNOWN without an explicit expression seed or propagation model",
                        call.location()));
            }
            methodCalls.put(call, new MethodCallTaint(call, receiver, arguments, result));
            return result;
        }

        private TaintValue evaluateObjectCreation(ObjectCreationExpression creation) {
            creation.arguments().forEach(this::evaluateExpression);
            if (!expressionSeeds.containsKey(creation)) {
                unsupported.add(new UnsupportedTaint(
                        "object creation result",
                        "Constructed object taint is UNKNOWN without an explicit model",
                        creation.location()));
            }
            return expressionSeeds.containsKey(creation)
                    ? TaintValue.clean()
                    : TaintValue.unknown();
        }

        private TaintValue evaluateFieldAccess(FieldAccessExpression field) {
            evaluateExpression(field.target());
            if (!expressionSeeds.containsKey(field)) {
                unsupported.add(new UnsupportedTaint(
                        "field access result",
                        "Field value taint is UNKNOWN without field-sensitive analysis",
                        field.location()));
            }
            return expressionSeeds.containsKey(field)
                    ? TaintValue.clean()
                    : TaintValue.unknown();
        }

        private TaintValue applyExpressionSeeds(Expression expression, TaintValue value) {
            TaintValue result = value;
            for (TaintSeed seed : expressionSeeds.getOrDefault(expression, List.of())) {
                result = result.join(TaintValue.tainted(seed));
                addEdge(step(seed), terminalStep(expression));
            }
            return result;
        }

        private void connectTaintedChildren(
                List<Expression> children,
                List<TaintValue> values,
                Expression parent,
                TaintValue parentValue) {
            if (parentValue.state() != TaintState.TAINTED) {
                return;
            }
            for (int index = 0; index < children.size(); index++) {
                if (values.get(index).state() == TaintState.TAINTED) {
                    addEdge(terminalStep(children.get(index)), step(parent));
                }
            }
        }

        private TaintTraceStep terminalStep(Expression expression) {
            if (expression instanceof VariableReference reference) {
                Optional<UseSite> useSite = dataFlow.useSite(reference);
                if (useSite.isPresent()) {
                    return step(useSite.orElseThrow());
                }
            }
            return step(expression);
        }

        private TaintTraceStep step(TaintSeed seed) {
            return seedSteps.computeIfAbsent(seed, ignored -> addStep(new TaintTraceStep(
                    nextTraceStepId++,
                    TaintTraceStepKind.SEED,
                    Optional.of(seed),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty())));
        }

        private TaintTraceStep step(Definition definition) {
            return definitionSteps.computeIfAbsent(definition, ignored -> addStep(new TaintTraceStep(
                    nextTraceStepId++,
                    TaintTraceStepKind.DEFINITION,
                    Optional.empty(),
                    Optional.of(definition),
                    Optional.empty(),
                    Optional.empty())));
        }

        private TaintTraceStep step(UseSite useSite) {
            return useSteps.computeIfAbsent(useSite, ignored -> addStep(new TaintTraceStep(
                    nextTraceStepId++,
                    TaintTraceStepKind.USE,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(useSite),
                    Optional.empty())));
        }

        private TaintTraceStep step(Expression expression) {
            return expressionSteps.computeIfAbsent(expression, ignored -> addStep(new TaintTraceStep(
                    nextTraceStepId++,
                    TaintTraceStepKind.EXPRESSION,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(expression))));
        }

        private TaintTraceStep addStep(TaintTraceStep step) {
            traceSteps.add(step);
            return step;
        }

        private void addEdge(TaintTraceStep source, TaintTraceStep target) {
            if (!source.equals(target)) {
                traceEdges.add(new TaintTraceEdge(source, target));
            }
        }

        private TaintAnalysisResult toResult() {
            LinkedHashMap<Definition, TaintTraceStep> definitionStepCopy = new LinkedHashMap<>();
            definitionSteps.forEach(definitionStepCopy::put);
            return new TaintAnalysisResult(
                    dataFlow,
                    seeds,
                    definitionTaints,
                    expressionTaints,
                    useSiteTaints,
                    methodCalls,
                    List.copyOf(unsupported),
                    traceSteps,
                    traceEdges,
                    definitionStepCopy,
                    useSteps,
                    evaluationCounts);
        }
    }

    private static final class ExpressionIndex {
        private final Set<Expression> identities =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private final List<Expression> expressions = new ArrayList<>();

        private static ExpressionIndex build(DataFlowResult dataFlow) {
            ExpressionIndex index = new ExpressionIndex();
            for (BasicBlock block : dataFlow.graph().blocks()) {
                if (!dataFlow.graph().reachableBlocks().contains(block)) {
                    continue;
                }
                block.controlStatement().ifPresent(index::collectControl);
                block.statements().forEach(index::collectStatement);
            }
            return index;
        }

        private void collectControl(Statement statement) {
            switch (statement) {
                case IfStatement conditional -> collect(conditional.condition());
                case WhileStatement loop -> collect(loop.condition());
                case DoWhileStatement loop -> collect(loop.condition());
                case ForStatement loop -> loop.condition().ifPresent(this::collect);
                case EnhancedForStatement loop -> collect(loop.iterable());
                case SwitchStatement selection -> collect(selection.selector());
                default -> {
                    // Only the expression evaluated by this control block belongs here.
                }
            }
        }

        private void collectStatement(Statement statement) {
            switch (statement) {
                case VariableDeclarationStatement declaration -> declaration.variables().forEach(
                        variable -> variable.initializer().ifPresent(this::collect));
                case ExpressionStatement expression -> collect(expression.expression());
                case ReturnStatement returned -> returned.expression().ifPresent(this::collect);
                case ThrowStatement thrown -> collect(thrown.expression());
                default -> {
                    // CFG stores nested control expressions in their own control blocks.
                }
            }
        }

        private void collect(Expression expression) {
            if (!identities.add(expression)) {
                return;
            }
            expressions.add(expression);
            switch (expression) {
                case VariableReference ignored -> {
                    // Leaf expression.
                }
                case Literal ignored -> {
                    // Leaf expression.
                }
                case UnknownExpression ignored -> {
                    // Leaf expression.
                }
                case BinaryExpression binary -> {
                    collect(binary.left());
                    collect(binary.right());
                }
                case AssignmentExpression assignment -> {
                    AssignmentInfo info = assignment.assignment();
                    if (!info.operator().equals("=")) {
                        collect(info.left());
                    } else if (info.left() instanceof FieldAccessExpression field) {
                        collect(field.target());
                    }
                    collect(info.right());
                }
                case MethodCallExpression call -> {
                    call.call().receiver().ifPresent(this::collect);
                    call.call().arguments().forEach(this::collect);
                }
                case ObjectCreationExpression creation -> creation.arguments().forEach(this::collect);
                case FieldAccessExpression field -> collect(field.target());
                case ParenthesizedExpression parenthesized -> collect(parenthesized.expression());
            }
        }

        private boolean contains(Expression expression) {
            return identities.contains(expression);
        }

        private List<Expression> expressions() {
            return List.copyOf(expressions);
        }
    }
}
