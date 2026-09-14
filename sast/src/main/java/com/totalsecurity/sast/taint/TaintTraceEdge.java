package com.totalsecurity.sast.taint;

import java.util.Objects;

public record TaintTraceEdge(TaintTraceStep source, TaintTraceStep target) {
    public TaintTraceEdge {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
    }
}
