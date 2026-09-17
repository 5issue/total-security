package com.totalsecurity.sast.detector.deserialization;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.taint.TaintState;
import java.util.List;
import java.util.Objects;

/** One exact ObjectInputStream.readObject occurrence and all supported possible input lineages. */
public record NativeDeserializationUse(
        TaintState inputState,
        List<DeserializationLineage> lineages,
        SourceLocation readObjectLocation) {
    public NativeDeserializationUse {
        Objects.requireNonNull(inputState, "inputState");
        lineages = List.copyOf(lineages);
        Objects.requireNonNull(readObjectLocation, "readObjectLocation");
    }
}
