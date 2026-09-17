package com.totalsecurity.sast.detector.redirect;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** High-confidence CWE-601 detector for supported full/prefix-controlled redirect targets. */
public final class OpenRedirectDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "OPEN_REDIRECT";
    public static final String VULNERABILITY_TYPE = "Open Redirect";
    public static final String CWE = "CWE-601";
    public static final FindingSeverity SEVERITY = FindingSeverity.MEDIUM;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        RedirectTargetControlAnalysis controls = new RedirectTargetControlAnalysis(analysis);
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.REDIRECT_TARGET,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (ignored, sink, argumentIndex) -> controls.classify(
                                sink.call().call().arguments().get(argumentIndex))
                        == RedirectTargetControl.FULLY_CONTROLLED,
                (sink, argumentIndex) ->
                        "Tainted external input controls a supported HTTP redirect target.");
    }
}
