package com.totalsecurity.sast.taint.model;

/** Explicit precedence for competing call-taint models. */
public enum MethodTaintModelPriority {
    GENERIC_PROPAGATION(100),
    FRAMEWORK_SPECIFIC_PROPAGATION(200),
    SANITIZER(300);

    private final int rank;

    MethodTaintModelPriority(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }
}
