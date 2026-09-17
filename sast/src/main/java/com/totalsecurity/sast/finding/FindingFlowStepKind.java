package com.totalsecurity.sast.finding;

public enum FindingFlowStepKind {
    SOURCE,
    DEFINITION,
    USE,
    EXPRESSION,
    METHOD_CALL,
    PARAMETER_BINDING,
    METHOD_RETURN,
    SINK
}
