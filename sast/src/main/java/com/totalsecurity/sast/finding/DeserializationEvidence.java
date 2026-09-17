package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** One exact constructor or use occurrence in a supported deserialization lineage. */
public record DeserializationEvidence(String api, String detail, SourceLocation location) {
    public DeserializationEvidence {
        requireText(api, "api");
        requireText(detail, "detail");
        Objects.requireNonNull(location, "location");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
