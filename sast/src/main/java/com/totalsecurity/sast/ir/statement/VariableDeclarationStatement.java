package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.VariableInfo;
import java.util.List;
import java.util.Objects;

public record VariableDeclarationStatement(
        List<VariableInfo> variables, SourceLocation location) implements Statement {
    public VariableDeclarationStatement {
        variables = List.copyOf(variables);
        Objects.requireNonNull(location, "location");
    }
}

