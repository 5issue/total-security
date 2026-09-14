package com.totalsecurity.sast.rule;

import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import com.totalsecurity.sast.taint.TaintValue;
import java.util.List;
import java.util.Objects;

/** Rule matching and taint propagation output without vulnerability classification. */
public record RuleAwareTaintResult(
        List<SourceMatch> sourceMatches,
        List<TaintSeed> taintSeeds,
        TaintAnalysisResult taintResult,
        List<SinkMatch> sinkMatches) {
    public RuleAwareTaintResult {
        sourceMatches = List.copyOf(sourceMatches);
        taintSeeds = List.copyOf(taintSeeds);
        Objects.requireNonNull(taintResult, "taintResult");
        sinkMatches = List.copyOf(sinkMatches);
    }

    public TaintValue sinkArgumentTaint(SinkMatch sink, int argumentIndex) {
        if (!sinkMatches.contains(sink)) {
            throw new IllegalArgumentException("Sink match is not part of this rule-aware result");
        }
        if (!sink.sensitiveArgumentIndexes().contains(argumentIndex)) {
            throw new IllegalArgumentException("Argument is not a sensitive position for this sink");
        }
        return taintResult.argumentTaint(sink.call(), argumentIndex);
    }
}
