package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.cfg.BasicBlock;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.ir.statement.Statement;
import java.util.Objects;

/** A resolved variable read and the CFG/statement occurrence containing it. */
public record UseSite(
        VariableReference reference,
        VariableSymbol variable,
        BasicBlock block,
        Statement statement) {
    public UseSite {
        Objects.requireNonNull(reference, "reference");
        Objects.requireNonNull(variable, "variable");
        Objects.requireNonNull(block, "block");
        Objects.requireNonNull(statement, "statement");
    }
}
