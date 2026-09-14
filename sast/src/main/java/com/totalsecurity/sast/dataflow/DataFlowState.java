package com.totalsecurity.sast.dataflow;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable mapping from variable identities to their currently reaching definitions. */
public final class DataFlowState {
    private static final DataFlowState EMPTY = new DataFlowState(Map.of());

    private final Map<VariableSymbol, Set<Definition>> definitions;

    private DataFlowState(Map<VariableSymbol, Set<Definition>> definitions) {
        LinkedHashMap<VariableSymbol, Set<Definition>> copied = new LinkedHashMap<>();
        definitions.forEach((symbol, values) -> {
            Objects.requireNonNull(symbol, "symbol");
            if (!values.isEmpty()) {
                copied.put(symbol, Collections.unmodifiableSet(new LinkedHashSet<>(values)));
            }
        });
        this.definitions = Collections.unmodifiableMap(copied);
    }

    public static DataFlowState empty() {
        return EMPTY;
    }

    public static DataFlowState join(Collection<DataFlowState> states) {
        if (states.isEmpty()) {
            return empty();
        }
        LinkedHashMap<VariableSymbol, Set<Definition>> joined = new LinkedHashMap<>();
        for (DataFlowState state : states) {
            Objects.requireNonNull(state, "state");
            state.definitions.forEach((symbol, values) ->
                    joined.computeIfAbsent(symbol, ignored -> new LinkedHashSet<>()).addAll(values));
        }
        return joined.isEmpty() ? empty() : new DataFlowState(joined);
    }

    /** Kills prior definitions of the same symbol and generates the supplied definition. */
    public DataFlowState redefine(Definition definition) {
        Objects.requireNonNull(definition, "definition");
        LinkedHashMap<VariableSymbol, Set<Definition>> updated = new LinkedHashMap<>(definitions);
        updated.put(definition.variable(), Set.of(definition));
        return new DataFlowState(updated);
    }

    public Set<Definition> definitionsOf(VariableSymbol symbol) {
        Objects.requireNonNull(symbol, "symbol");
        return definitions.getOrDefault(symbol, Set.of());
    }

    public Map<VariableSymbol, Set<Definition>> asMap() {
        return definitions;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DataFlowState state && definitions.equals(state.definitions);
    }

    @Override
    public int hashCode() {
        return definitions.hashCode();
    }

    @Override
    public String toString() {
        return definitions.toString();
    }
}
