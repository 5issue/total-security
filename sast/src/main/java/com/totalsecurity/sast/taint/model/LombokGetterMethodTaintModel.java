package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;

/** Whole-receiver may-taint for an exact source-proven compiler-generated Lombok getter. */
public final class LombokGetterMethodTaintModel implements MethodTaintModel {
    public static final String ID = "LOMBOK_EXACT_GETTER";

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
        return context.lombokGetter().isPresent()
                ? Optional.of(MethodTaintSemantics.propagateReceiver())
                : Optional.empty();
    }
}
