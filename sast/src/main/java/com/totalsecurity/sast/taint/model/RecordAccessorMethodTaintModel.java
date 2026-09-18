package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;

/** Receiver-derived taint for an exact compiler-provided record component accessor. */
public final class RecordAccessorMethodTaintModel implements MethodTaintModel {
    public static final String ID = "JAVA_RECORD_COMPONENT_ACCESSOR";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public MethodTaintModelPriority priority() {
        return MethodTaintModelPriority.LANGUAGE_SPECIFIC_PROPAGATION;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        return context.recordAccessor().isPresent()
                ? Optional.of(MethodTaintSemantics.propagateReceiver())
                : Optional.empty();
    }
}
