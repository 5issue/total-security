package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.cfg.ControlFlowGraph;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.Statement;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Immutable result of one intraprocedural reaching-definitions analysis. */
public final class DataFlowResult {
    private final ControlFlowGraph graph;
    private final Map<BasicBlock, DataFlowState> inStates;
    private final Map<BasicBlock, DataFlowState> outStates;
    private final Map<Statement, DataFlowState> statementBeforeStates;
    private final Map<VariableReference, UseSite> useSites;
    private final Map<VariableReference, Set<Definition>> reachingDefinitionsByUse;
    private final Map<VariableReference, VariableSymbol> resolvedSymbols;
    private final List<VariableSymbol> symbols;
    private final List<Definition> definitions;
    private final List<UnresolvedReference> unresolvedReferences;
    private final List<UnsupportedDataFlow> unsupportedDataFlow;
    private final Map<BasicBlock, Integer> evaluationCounts;

    DataFlowResult(
            ControlFlowGraph graph,
            Map<BasicBlock, DataFlowState> inStates,
            Map<BasicBlock, DataFlowState> outStates,
            Map<Statement, DataFlowState> statementBeforeStates,
            Map<VariableReference, UseSite> useSites,
            Map<VariableReference, Set<Definition>> reachingDefinitionsByUse,
            Map<VariableReference, VariableSymbol> resolvedSymbols,
            List<VariableSymbol> symbols,
            List<Definition> definitions,
            List<UnresolvedReference> unresolvedReferences,
            List<UnsupportedDataFlow> unsupportedDataFlow,
            Map<BasicBlock, Integer> evaluationCounts) {
        this.graph = Objects.requireNonNull(graph, "graph");
        this.inStates = immutableMap(inStates);
        this.outStates = immutableMap(outStates);
        this.statementBeforeStates = immutableMap(statementBeforeStates);
        this.useSites = immutableMap(useSites);
        this.reachingDefinitionsByUse = immutableSetMap(reachingDefinitionsByUse);
        this.resolvedSymbols = immutableMap(resolvedSymbols);
        this.symbols = List.copyOf(symbols);
        this.definitions = List.copyOf(definitions);
        this.unresolvedReferences = List.copyOf(unresolvedReferences);
        this.unsupportedDataFlow = List.copyOf(unsupportedDataFlow);
        this.evaluationCounts = immutableMap(evaluationCounts);
    }

    public ControlFlowGraph graph() {
        return graph;
    }

    public Map<BasicBlock, DataFlowState> inStates() {
        return inStates;
    }

    public Map<BasicBlock, DataFlowState> outStates() {
        return outStates;
    }

    public Optional<DataFlowState> inState(BasicBlock block) {
        return Optional.ofNullable(inStates.get(block));
    }

    public Optional<DataFlowState> outState(BasicBlock block) {
        return Optional.ofNullable(outStates.get(block));
    }

    public Optional<DataFlowState> stateBefore(Statement statement) {
        return Optional.ofNullable(statementBeforeStates.get(statement));
    }

    public List<UseSite> useSites() {
        return List.copyOf(useSites.values());
    }

    public Optional<UseSite> useSite(VariableReference reference) {
        return Optional.ofNullable(useSites.get(reference));
    }

    public Set<Definition> reachingDefinitions(VariableReference reference) {
        return reachingDefinitionsByUse.getOrDefault(reference, Set.of());
    }

    public Optional<VariableSymbol> resolvedSymbol(VariableReference reference) {
        return Optional.ofNullable(resolvedSymbols.get(reference));
    }

    public List<VariableSymbol> symbols() {
        return symbols;
    }

    public List<Definition> definitions() {
        return definitions;
    }

    public Set<Definition> definitionsFor(VariableSymbol symbol) {
        return definitions.stream()
                .filter(definition -> definition.variable().equals(symbol))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public List<UnresolvedReference> unresolvedReferences() {
        return unresolvedReferences;
    }

    public List<UnsupportedDataFlow> unsupportedDataFlow() {
        return unsupportedDataFlow;
    }

    public int evaluationCount(BasicBlock block) {
        return evaluationCounts.getOrDefault(block, 0);
    }

    private static <K, V> Map<K, V> immutableMap(Map<K, V> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    private static <K, V> Map<K, Set<V>> immutableSetMap(Map<K, Set<V>> source) {
        LinkedHashMap<K, Set<V>> copied = new LinkedHashMap<>();
        source.forEach((key, value) -> copied.put(key, Set.copyOf(value)));
        return Collections.unmodifiableMap(copied);
    }
}
