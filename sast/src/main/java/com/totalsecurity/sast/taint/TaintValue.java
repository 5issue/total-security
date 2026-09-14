package com.totalsecurity.sast.taint;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/** A lattice value plus the externally supplied seeds that justify TAINTED. */
public record TaintValue(TaintState state, Set<TaintSeed> origins) {
    private static final TaintValue CLEAN = new TaintValue(TaintState.CLEAN, Set.of());
    private static final TaintValue UNKNOWN = new TaintValue(TaintState.UNKNOWN, Set.of());

    public TaintValue {
        Objects.requireNonNull(state, "state");
        origins = Collections.unmodifiableSet(new LinkedHashSet<>(origins));
        if (state != TaintState.TAINTED && !origins.isEmpty()) {
            throw new IllegalArgumentException("Only TAINTED values may carry seed origins");
        }
    }

    public static TaintValue clean() {
        return CLEAN;
    }

    public static TaintValue unknown() {
        return UNKNOWN;
    }

    public static TaintValue tainted(TaintSeed seed) {
        return new TaintValue(TaintState.TAINTED, Set.of(Objects.requireNonNull(seed, "seed")));
    }

    public static TaintValue join(Collection<TaintValue> values) {
        TaintValue result = clean();
        for (TaintValue value : values) {
            result = result.join(value);
        }
        return result;
    }

    public TaintValue join(TaintValue other) {
        Objects.requireNonNull(other, "other");
        TaintState joinedState = state.join(other.state);
        if (joinedState != TaintState.TAINTED) {
            return joinedState == TaintState.UNKNOWN ? unknown() : clean();
        }
        LinkedHashSet<TaintSeed> joinedOrigins = new LinkedHashSet<>(origins);
        joinedOrigins.addAll(other.origins);
        return new TaintValue(TaintState.TAINTED, joinedOrigins);
    }
}
