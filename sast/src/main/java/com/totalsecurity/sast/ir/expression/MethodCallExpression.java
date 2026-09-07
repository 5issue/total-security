package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.MethodCallInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record MethodCallExpression(MethodCallInfo call) implements Expression {
    public MethodCallExpression {
        Objects.requireNonNull(call, "call");
    }

    @Override
    public SourceLocation location() {
        return call.location();
    }
}

