package com.totalsecurity.sast.detector.xxe;

import com.totalsecurity.sast.finding.ConfigurationEvidence;
import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** A supported DOM parse occurrence whose builder snapshot is explicitly unsafe. */
public record UnsafeDomParserUse(
        String factoryType,
        String parserType,
        Set<ExternalResolutionPath> provenPaths,
        List<ConfigurationEvidence> provenConfigurations,
        SourceLocation parserCreationLocation,
        SourceLocation parseLocation) {
    public UnsafeDomParserUse {
        Objects.requireNonNull(factoryType, "factoryType");
        Objects.requireNonNull(parserType, "parserType");
        provenPaths = Set.copyOf(provenPaths);
        if (provenPaths.isEmpty()) {
            throw new IllegalArgumentException("provenPaths must not be empty");
        }
        provenConfigurations = List.copyOf(provenConfigurations);
        if (provenConfigurations.isEmpty()) {
            throw new IllegalArgumentException("provenConfigurations must not be empty");
        }
        Objects.requireNonNull(parserCreationLocation, "parserCreationLocation");
        Objects.requireNonNull(parseLocation, "parseLocation");
    }
}
