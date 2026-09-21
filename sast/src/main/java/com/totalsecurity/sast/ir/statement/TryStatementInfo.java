package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Structural metadata for a try statement that remains unsupported by the general CFG.
 * Consumers may use it only for conservative, shape-specific proofs.
 */
public record TryStatementInfo(
        BlockStatement body,
        List<CatchClauseInfo> catches,
        Optional<BlockStatement> finallyBlock,
        boolean resourcesPresent,
        SourceLocation location) {
    public TryStatementInfo {
        Objects.requireNonNull(body, "body");
        catches = List.copyOf(catches);
        finallyBlock = Objects.requireNonNull(finallyBlock, "finallyBlock");
        Objects.requireNonNull(location, "location");
    }
}
