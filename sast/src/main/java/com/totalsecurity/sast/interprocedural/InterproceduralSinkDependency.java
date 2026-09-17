package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.finding.FindingFlowStep;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public record InterproceduralSinkDependency(
        SinkMatch sink,
        int argumentIndex,
        Set<Integer> parameterIndexes,
        Map<Integer, List<FindingFlowStep>> parameterFlows,
        List<InterproceduralCallBoundary> callChain) {
    public InterproceduralSinkDependency {
        parameterIndexes = Set.copyOf(parameterIndexes);
        LinkedHashMap<Integer, List<FindingFlowStep>> copied = new LinkedHashMap<>();
        parameterFlows.forEach((index, steps) -> copied.put(index, List.copyOf(steps)));
        parameterFlows = Map.copyOf(copied);
        callChain = List.copyOf(callChain);
        if (!sink.sensitiveArgumentIndexes().contains(argumentIndex)) {
            throw new IllegalArgumentException("Dependency argument is not a sink position");
        }
    }
}
