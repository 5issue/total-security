package com.totalsecurity.sast.cfg;

public enum BasicBlockKind {
    ENTRY,
    EXIT,
    STATEMENTS,
    CONDITION,
    LOOP_HEADER,
    LOOP_UPDATE,
    SWITCH_SELECTOR,
    SWITCH_CASE,
    MERGE
}

