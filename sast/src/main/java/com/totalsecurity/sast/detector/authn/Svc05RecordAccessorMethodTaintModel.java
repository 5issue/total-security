package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;
import com.totalsecurity.sast.taint.model.MethodTaintSemantics;
import java.util.Optional;
import java.util.Set;

/** SVC-05 record propagation that exposes only the token component of issuer results. */
final class Svc05RecordAccessorMethodTaintModel implements MethodTaintModel {
    static final String ID = "SVC_05_RECORD_COMPONENT_PROPAGATION";
    private final Set<String> issuedTokenRecords;

    Svc05RecordAccessorMethodTaintModel(Set<String> issuedTokenRecords) {
        this.issuedTokenRecords = Set.copyOf(issuedTokenRecords);
    }

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
        if (context.recordAccessor().isEmpty()) {
            return Optional.empty();
        }
        var accessor = context.recordAccessor().orElseThrow();
        if (!issuedTokenRecords.contains(accessor.ownerQualifiedName())) {
            return Optional.of(MethodTaintSemantics.propagateReceiver());
        }
        return accessor.component().name().equals("token")
                        && accessor.qualifiedReturnType().equals("java.lang.String")
                ? Optional.of(MethodTaintSemantics.propagateReceiver())
                : Optional.of(MethodTaintSemantics.cleanReturn());
    }
}
