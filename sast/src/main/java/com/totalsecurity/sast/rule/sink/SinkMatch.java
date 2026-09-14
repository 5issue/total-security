package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public record SinkMatch(
        String ruleId,
        MethodCallExpression call,
        Set<Integer> sensitiveArgumentIndexes,
        SourceLocation location,
        String evidence) {
    public SinkMatch {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(call, "call");
        sensitiveArgumentIndexes = Set.copyOf(new LinkedHashSet<>(sensitiveArgumentIndexes));
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(evidence, "evidence");
        if (sensitiveArgumentIndexes.isEmpty()
                || sensitiveArgumentIndexes.stream().anyMatch(index -> index < 0 || index >= call.call().arguments().size())) {
            throw new IllegalArgumentException("Sensitive argument indexes must reference this call");
        }
    }
}
