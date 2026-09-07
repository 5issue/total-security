package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;

public sealed interface Expression
        permits VariableReference,
                Literal,
                BinaryExpression,
                AssignmentExpression,
                MethodCallExpression,
                ObjectCreationExpression,
                FieldAccessExpression,
                ParenthesizedExpression,
                UnknownExpression {
    SourceLocation location();
}
