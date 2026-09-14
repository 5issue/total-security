package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.taint.TaintSeed;

public sealed interface SourceMatch permits ParameterSourceMatch, ExpressionSourceMatch {
    String ruleId();

    SourceLocation location();

    String evidence();

    TaintSeed toTaintSeed(DataFlowResult dataFlow);
}
