package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;

public interface SinkRule {
    String id();

    Optional<SinkMatch> match(CallSiteContext context);
}
