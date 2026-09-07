package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.AssignmentInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record AssignmentExpression(AssignmentInfo assignment) implements Expression {
    public AssignmentExpression {
        Objects.requireNonNull(assignment, "assignment");
    }

    @Override
    public SourceLocation location() {
        return assignment.location();
    }
}

