package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.Objects;

public record FindingSink(
        String sinkRuleId,
        SinkCategory category,
        String methodName,
        int argumentIndex,
        SourceLocation location) {
    public FindingSink {
        if (sinkRuleId == null || sinkRuleId.isBlank()) {
            throw new IllegalArgumentException("sinkRuleId must not be blank");
        }
        Objects.requireNonNull(category, "category");
        if (methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("methodName must not be blank");
        }
        if (argumentIndex < 0) {
            throw new IllegalArgumentException("argumentIndex must be non-negative");
        }
        Objects.requireNonNull(location, "location");
    }
}
