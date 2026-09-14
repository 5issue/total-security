package com.totalsecurity.sast.taint;

public enum TaintState {
    CLEAN,
    UNKNOWN,
    TAINTED;

    public TaintState join(TaintState other) {
        if (this == TAINTED || other == TAINTED) {
            return TAINTED;
        }
        if (this == UNKNOWN || other == UNKNOWN) {
            return UNKNOWN;
        }
        return CLEAN;
    }
}
