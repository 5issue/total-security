package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;

public interface MethodTaintModel {
    String id();

    default MethodTaintModelPriority priority() {
        return MethodTaintModelPriority.GENERIC_PROPAGATION;
    }

    Optional<MethodTaintSemantics> match(CallSiteContext context);
}
