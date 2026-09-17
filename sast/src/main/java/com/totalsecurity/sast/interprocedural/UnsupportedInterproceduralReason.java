package com.totalsecurity.sast.interprocedural;

public enum UnsupportedInterproceduralReason {
    AMBIGUOUS_OVERLOAD,
    UNKNOWN_ARGUMENT_TYPE,
    INCOMPATIBLE_ARGUMENT_TYPE,
    WRONG_ARITY,
    DYNAMIC_RECEIVER,
    INHERITED_METHOD,
    RECURSIVE_CALL
}
