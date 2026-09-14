package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.statement.Statement;
import java.util.Objects;
import java.util.Optional;

/** A stable definition occurrence used by the reaching-definitions lattice. */
public record Definition(
        int id,
        VariableSymbol variable,
        DefinitionKind kind,
        Optional<Expression> assignedExpression,
        Optional<String> assignmentOperator,
        SourceLocation location,
        Optional<Statement> statement) {
    public Definition {
        if (id < 0) {
            throw new IllegalArgumentException("Definition id must be non-negative");
        }
        Objects.requireNonNull(variable, "variable");
        Objects.requireNonNull(kind, "kind");
        assignedExpression = Objects.requireNonNull(assignedExpression, "assignedExpression");
        assignmentOperator = Objects.requireNonNull(assignmentOperator, "assignmentOperator");
        Objects.requireNonNull(location, "location");
        statement = Objects.requireNonNull(statement, "statement");
    }
}
