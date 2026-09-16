package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** One explicit security-relevant configuration write retained as finding evidence. */
public record ConfigurationEvidence(
        String api,
        String configurationKey,
        String configuredValue,
        SourceLocation location) {
    public ConfigurationEvidence {
        requireText(api, "api");
        requireText(configurationKey, "configurationKey");
        Objects.requireNonNull(configuredValue, "configuredValue");
        Objects.requireNonNull(location, "location");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
