package com.totalsecurity.sast.taint;

import java.util.Set;
import java.util.Objects;

/** A cycle-safe provenance subgraph ending at one queried use site. */
public record TaintTrace(
        TaintTraceStep target, Set<TaintTraceStep> steps, Set<TaintTraceEdge> edges) {
    public TaintTrace {
        Objects.requireNonNull(target, "target");
        steps = Set.copyOf(steps);
        edges = Set.copyOf(edges);
        if (!steps.contains(target)) {
            throw new IllegalArgumentException("Trace steps must contain the target");
        }
    }
}
