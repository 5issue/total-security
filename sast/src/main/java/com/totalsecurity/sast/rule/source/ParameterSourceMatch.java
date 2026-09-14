package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.dataflow.Definition;
import com.totalsecurity.sast.dataflow.DefinitionKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.taint.DefinitionTaintSeed;
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.Objects;

public record ParameterSourceMatch(String ruleId, ParameterInfo parameter, String evidence)
        implements SourceMatch {
    public ParameterSourceMatch {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(parameter, "parameter");
        Objects.requireNonNull(evidence, "evidence");
    }

    @Override
    public SourceLocation location() {
        return parameter.location();
    }

    @Override
    public TaintSeed toTaintSeed(DataFlowResult dataFlow) {
        Definition definition = dataFlow.definitions().stream()
                .filter(candidate -> candidate.kind() == DefinitionKind.PARAMETER)
                .filter(candidate -> candidate.variable().name().equals(parameter.name()))
                .filter(candidate -> candidate.location().equals(parameter.location()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Matched parameter is not part of this DataFlowResult"));
        return new DefinitionTaintSeed(seedId(ruleId, location()), definition);
    }

    private static String seedId(String ruleId, SourceLocation location) {
        return ruleId + "@" + location.file() + ":" + location.startLine() + ":" + location.startColumn();
    }
}
