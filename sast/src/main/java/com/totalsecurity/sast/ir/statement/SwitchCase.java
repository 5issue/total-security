package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.List;
import java.util.Objects;

public record SwitchCase(
        List<Expression> labels,
        boolean defaultCase,
        List<Statement> statements,
        SourceLocation location) {
    public SwitchCase {
        labels = List.copyOf(labels);
        statements = List.copyOf(statements);
        Objects.requireNonNull(location, "location");
    }
}

