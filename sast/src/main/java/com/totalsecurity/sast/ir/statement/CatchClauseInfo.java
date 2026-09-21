package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Tree-sitter-independent structure retained for an otherwise unsupported catch clause. */
public record CatchClauseInfo(BlockStatement body, SourceLocation location) {
    public CatchClauseInfo {
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(location, "location");
    }
}
