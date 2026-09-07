package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.VariableInfo;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record EnhancedForStatement(
        VariableInfo variable, Expression iterable, Statement body, SourceLocation location)
        implements Statement {
    public EnhancedForStatement {
        Objects.requireNonNull(variable, "variable");
        Objects.requireNonNull(iterable, "iterable");
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(location, "location");
    }
}

