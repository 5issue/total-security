package com.totalsecurity.sast.pattern;

import com.totalsecurity.sast.finding.PatternFinding;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.pattern.authn.Authn06HardcodedSigningMaterialDetector;
import com.totalsecurity.sast.pattern.credential.HardcodedCredentialDetector;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Runs independent structural pattern detectors without CFG, data-flow, or taint analysis. */
public final class PatternAnalysis {
    private final List<PatternDetector> detectors;

    public PatternAnalysis(List<PatternDetector> detectors) {
        this.detectors = List.copyOf(detectors);
    }

    public static PatternAnalysis javaDefaults() {
        return new PatternAnalysis(List.of(
                new HardcodedCredentialDetector(),
                new Authn06HardcodedSigningMaterialDetector()));
    }

    public List<PatternFinding> analyze(JavaFileInfo file) {
        Objects.requireNonNull(file, "file");
        List<PatternFinding> findings = new ArrayList<>();
        for (PatternDetector detector : detectors) {
            findings.addAll(detector.detect(file));
        }
        return List.copyOf(findings);
    }

    public List<PatternDetector> detectors() {
        return detectors;
    }
}
