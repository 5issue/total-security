package com.totalsecurity.sast.ir;

import com.totalsecurity.sast.ir.expression.Expression;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record MethodCallInfo(
        Optional<Expression> receiver,
        String methodName,
        List<Expression> arguments,
        SourceLocation location) {
    public MethodCallInfo {
        receiver = Objects.requireNonNull(receiver, "receiver");
        Objects.requireNonNull(methodName, "methodName");
        arguments = List.copyOf(arguments);
        Objects.requireNonNull(location, "location");
    }
}

