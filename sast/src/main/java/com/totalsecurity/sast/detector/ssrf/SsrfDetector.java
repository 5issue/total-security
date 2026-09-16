package com.totalsecurity.sast.detector.ssrf;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** CWE-918 detector over confirmed taint at supported outbound request targets. */
public final class SsrfDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "SSRF";
    public static final String VULNERABILITY_TYPE = "Server-Side Request Forgery";
    public static final String CWE = "CWE-918";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.NETWORK_REQUEST_TARGET,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (sink, argumentIndex) -> "Tainted external input reaches a supported outbound "
                        + "network request target argument " + argumentIndex + " of sink rule "
                        + sink.ruleId() + ".");
    }
}
