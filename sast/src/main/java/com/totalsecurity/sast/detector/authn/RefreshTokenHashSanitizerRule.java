package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.sanitizer.SanitizerRule;
import com.totalsecurity.sast.taint.model.MethodTaintSemantics;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Exact project-local hash operation observed in the audited backend. */
final class RefreshTokenHashSanitizerRule implements SanitizerRule {
    static final String ID = "AUTHN_11_REFRESH_TOKEN_HASH";
    private final Set<String> verifiedOwners;

    RefreshTokenHashSanitizerRule(Set<String> verifiedOwners) {
        this.verifiedOwners = Set.copyOf(Objects.requireNonNull(
                verifiedOwners, "verifiedOwners"));
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        if (!context.receiverBoundToValue()
                || !context.methodName().equals("hash")
                || context.argumentCount() != 1
                || !context.argumentHasType(0, "java.lang.String")
                || context.receiverQualifiedType()
                        .filter(verifiedOwners::contains)
                        .isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(MethodTaintSemantics.sanitizedReturn());
    }
}
