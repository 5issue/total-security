package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.UseSite;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Immutable STEP 5 taint propagation result. */
public final class TaintAnalysisResult {
    private final DataFlowResult dataFlow;
    private final Set<TaintSeed> seeds;
    private final Map<Definition, TaintValue> definitionTaints;
    private final Map<Expression, TaintValue> expressionTaints;
    private final Map<UseSite, TaintValue> useSiteTaints;
    private final Map<MethodCallExpression, MethodCallTaint> methodCalls;
    private final List<UnsupportedTaint> unsupported;
    private final Set<TaintTraceStep> traceSteps;
    private final Set<TaintTraceEdge> traceEdges;
    private final Map<Definition, TaintTraceStep> definitionSteps;
    private final Map<UseSite, TaintTraceStep> useSteps;
    private final Map<Definition, Integer> evaluationCounts;

    TaintAnalysisResult(
            DataFlowResult dataFlow,
            Set<TaintSeed> seeds,
            Map<Definition, TaintValue> definitionTaints,
            Map<Expression, TaintValue> expressionTaints,
            Map<UseSite, TaintValue> useSiteTaints,
            Map<MethodCallExpression, MethodCallTaint> methodCalls,
            List<UnsupportedTaint> unsupported,
            Set<TaintTraceStep> traceSteps,
            Set<TaintTraceEdge> traceEdges,
            Map<Definition, TaintTraceStep> definitionSteps,
            Map<UseSite, TaintTraceStep> useSteps,
            Map<Definition, Integer> evaluationCounts) {
        this.dataFlow = Objects.requireNonNull(dataFlow, "dataFlow");
        this.seeds = Set.copyOf(seeds);
        this.definitionTaints = immutableMap(definitionTaints);
        this.expressionTaints = immutableMap(expressionTaints);
        this.useSiteTaints = immutableMap(useSiteTaints);
        this.methodCalls = immutableMap(methodCalls);
        this.unsupported = List.copyOf(unsupported);
        this.traceSteps = Set.copyOf(traceSteps);
        this.traceEdges = Set.copyOf(traceEdges);
        this.definitionSteps = immutableMap(definitionSteps);
        this.useSteps = immutableMap(useSteps);
        this.evaluationCounts = immutableMap(evaluationCounts);
    }

    public DataFlowResult dataFlow() {
        return dataFlow;
    }

    public Set<TaintSeed> seeds() {
        return seeds;
    }

    public TaintValue taintOf(Definition definition) {
        return require(definitionTaints, definition, "definition");
    }

    public TaintValue taintOf(Expression expression) {
        return require(expressionTaints, expression, "expression");
    }

    public TaintValue taintOf(VariableReference reference) {
        return taintOf((Expression) reference);
    }

    public TaintValue taintOf(UseSite useSite) {
        return require(useSiteTaints, useSite, "use site");
    }

    public Optional<MethodCallTaint> methodCallTaint(MethodCallExpression call) {
        return Optional.ofNullable(methodCalls.get(call));
    }

    public TaintValue argumentTaint(MethodCallExpression call, int index) {
        return methodCallTaint(call).orElseThrow(() ->
                        new IllegalArgumentException("Method call is not part of the analyzed reachable CFG"))
                .argument(index);
    }

    public Optional<TaintValue> receiverTaint(MethodCallExpression call) {
        return methodCallTaint(call).flatMap(MethodCallTaint::receiver);
    }

    public List<MethodCallTaint> methodCalls() {
        return List.copyOf(methodCalls.values());
    }

    public List<UnsupportedTaint> unsupported() {
        return unsupported;
    }

    public Set<TaintTraceStep> traceSteps() {
        return traceSteps;
    }

    public Set<TaintTraceEdge> traceEdges() {
        return traceEdges;
    }

    public TaintTrace traceTo(UseSite useSite) {
        TaintTraceStep target = useSteps.get(useSite);
        if (target == null) {
            throw new IllegalArgumentException("Use site has no taint provenance node");
        }
        LinkedHashSet<TaintTraceStep> steps = new LinkedHashSet<>();
        LinkedHashSet<TaintTraceEdge> edges = new LinkedHashSet<>();
        ArrayDeque<TaintTraceStep> work = new ArrayDeque<>();
        work.add(target);
        while (!work.isEmpty()) {
            TaintTraceStep current = work.removeFirst();
            if (!steps.add(current)) {
                continue;
            }
            traceEdges.stream()
                    .filter(edge -> edge.target().equals(current))
                    .forEach(edge -> {
                        edges.add(edge);
                        if (!steps.contains(edge.source())) {
                            work.addLast(edge.source());
                        }
                    });
        }
        return new TaintTrace(steps, edges);
    }

    public int evaluationCount(Definition definition) {
        return evaluationCounts.getOrDefault(definition, 0);
    }

    public Set<Definition> analyzedDefinitions() {
        return definitionTaints.keySet();
    }

    public Set<Expression> analyzedExpressions() {
        return expressionTaints.keySet();
    }

    private static <K, V> Map<K, V> immutableMap(Map<K, V> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    private static <K, V> V require(Map<K, V> values, K key, String kind) {
        Objects.requireNonNull(key, kind);
        V value = values.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Unknown or unreachable " + kind);
        }
        return value;
    }
}
