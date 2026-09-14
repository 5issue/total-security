package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.ParameterContext;
import java.util.Optional;

public interface SourceRule {
    String id();

    default Optional<SourceMatch> match(ParameterContext context) {
        return Optional.empty();
    }

    default Optional<SourceMatch> match(CallSiteContext context) {
        return Optional.empty();
    }
}
