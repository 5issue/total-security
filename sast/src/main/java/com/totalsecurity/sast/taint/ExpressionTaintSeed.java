package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record ExpressionTaintSeed(String id, Expression expression) implements TaintSeed {
    public ExpressionTaintSeed {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(expression, "expression");
    }

    @Override
    public SourceLocation location() {
        return expression.location();
    }
}
