package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;

public record ObjectCreationExpression(
        String typeName, List<Expression> arguments, SourceLocation location)
        implements Expression {
    public ObjectCreationExpression {
        Objects.requireNonNull(typeName, "typeName");
        arguments = List.copyOf(arguments);
        Objects.requireNonNull(location, "location");
    }
}

