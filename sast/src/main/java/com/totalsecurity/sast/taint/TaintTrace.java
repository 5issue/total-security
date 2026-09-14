package com.totalsecurity.sast.taint;

import java.util.Set;

/** A cycle-safe provenance subgraph ending at one queried use site. */
public record TaintTrace(Set<TaintTraceStep> steps, Set<TaintTraceEdge> edges) {
    public TaintTrace {
        steps = Set.copyOf(steps);
        edges = Set.copyOf(edges);
    }
}
