package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.List;
import java.util.Objects;

public record SwitchStatement(
        Expression selector, List<SwitchCase> cases, SourceLocation location) implements Statement {
    public SwitchStatement {
        Objects.requireNonNull(selector, "selector");
        cases = List.copyOf(cases);
        Objects.requireNonNull(location, "location");
    }
}

