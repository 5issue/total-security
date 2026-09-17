package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.finding.FindingFlowStep;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public record MethodReturnDependency(
        MethodReturnDependencyKind kind,
        Set<Integer> parameterIndexes,
        Map<Integer, List<FindingFlowStep>> parameterFlows) {
    public MethodReturnDependency {
        parameterIndexes = Set.copyOf(parameterIndexes);
        LinkedHashMap<Integer, List<FindingFlowStep>> copied = new LinkedHashMap<>();
        parameterFlows.forEach((index, steps) -> copied.put(index, List.copyOf(steps)));
        parameterFlows = Map.copyOf(copied);
        if (kind != MethodReturnDependencyKind.PARAMETER_DEPENDENT
                && (!parameterIndexes.isEmpty() || !parameterFlows.isEmpty())) {
            throw new IllegalArgumentException("Only dependent returns carry parameter flows");
        }
    }

    public static MethodReturnDependency clean() {
        return new MethodReturnDependency(MethodReturnDependencyKind.CLEAN, Set.of(), Map.of());
    }

    public static MethodReturnDependency unknown() {
        return new MethodReturnDependency(MethodReturnDependencyKind.UNKNOWN, Set.of(), Map.of());
    }
}
