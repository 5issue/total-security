package com.totalsecurity.sast.runner;

public record ProjectScanSummary(
        int discoveredJavaFiles,
        int successfullyParsedFiles,
        int successfullyExtractedFiles,
        int diagnostics,
        int findings,
        int unsupportedInterproceduralFlows) {
    public ProjectScanSummary {
        if (discoveredJavaFiles < 0
                || successfullyParsedFiles < 0
                || successfullyExtractedFiles < 0
                || diagnostics < 0
                || findings < 0
                || unsupportedInterproceduralFlows < 0) {
            throw new IllegalArgumentException("Scan counts must be non-negative");
        }
    }
}
