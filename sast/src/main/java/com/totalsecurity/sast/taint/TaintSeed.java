package com.totalsecurity.sast.taint;

import com.totalsecurity.sast.ir.SourceLocation;

/** An externally supplied source fact. STEP 5 does not infer seeds from framework APIs. */
public sealed interface TaintSeed permits DefinitionTaintSeed, ExpressionTaintSeed {
    String id();

    SourceLocation location();
}
