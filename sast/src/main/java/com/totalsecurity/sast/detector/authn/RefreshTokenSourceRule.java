package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.ParameterContext;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.rule.source.SourceRule;
import java.util.Optional;

/** AUTHN-11 sources proven by raw refresh-token parameters or the audited issuer API. */
final class RefreshTokenSourceRule implements SourceRule {
    static final String ID = "AUTHN_11_REFRESH_TOKEN_SOURCE";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SourceMatch> match(ParameterContext context) {
        if (!Authn11Names.isRawRefreshTokenIdentifier(context.parameter().name())
                || context.types().qualifyTypeShape(context.parameter().type())
                        .filter("java.lang.String"::equals).isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ParameterSourceMatch(
                ID,
                context.parameter(),
                "raw refresh-token parameter proven by identifier and String type"));
    }

    @Override
    public Optional<SourceMatch> match(CallSiteContext context) {
        if (!context.receiverBoundToValue()
                || !context.methodName().equals("issueRefreshToken")
                || context.argumentCount() != 2
                || context.receiverQualifiedType()
                        .map(Authn11Names::simpleName)
                        .filter("JwtTokenProvider"::equals)
                        .isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ExpressionSourceMatch(
                ID,
                context.call(),
                "return value of exact JwtTokenProvider.issueRefreshToken call"));
    }
}
