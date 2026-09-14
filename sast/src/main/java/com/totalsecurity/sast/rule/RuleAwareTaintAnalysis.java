package com.totalsecurity.sast.rule;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.taint.IntraproceduralTaintAnalysis;
import com.totalsecurity.sast.taint.TaintAnalysisResult;
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.List;
import java.util.Objects;

/** Recommended STEP 6+ entry point that cannot omit registered call semantics. */
public final class RuleAwareTaintAnalysis {
    private final IntraproceduralTaintAnalysis taintAnalysis;

    public RuleAwareTaintAnalysis() {
        this(new IntraproceduralTaintAnalysis());
    }

    RuleAwareTaintAnalysis(IntraproceduralTaintAnalysis taintAnalysis) {
        this.taintAnalysis = Objects.requireNonNull(taintAnalysis, "taintAnalysis");
    }

    public RuleAwareTaintResult analyze(
            JavaFileInfo file,
            ClassInfo type,
            MethodInfo method,
            DataFlowResult dataFlow,
            RuleRegistry rules) {
        Objects.requireNonNull(rules, "rules");
        List<SourceMatch> sourceMatches = rules.matchSources(file, type, method, dataFlow);
        List<TaintSeed> seeds = sourceMatches.stream()
                .map(match -> match.toTaintSeed(dataFlow))
                .toList();
        TaintAnalysisResult taintResult = taintAnalysis.analyze(
                dataFlow,
                seeds,
                rules.methodSemantics(file, type, method, dataFlow));
        List<SinkMatch> sinkMatches = rules.matchSinks(file, type, method, dataFlow);
        return new RuleAwareTaintResult(sourceMatches, seeds, taintResult, sinkMatches);
    }
}
