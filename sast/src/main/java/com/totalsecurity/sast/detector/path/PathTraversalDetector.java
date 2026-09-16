package com.totalsecurity.sast.detector.path;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** CWE-22 detector over confirmed taint at supported filesystem Path arguments. */
public final class PathTraversalDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "PATH_TRAVERSAL";
    public static final String VULNERABILITY_TYPE = "Path Traversal";
    public static final String CWE = "CWE-22";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.FILESYSTEM_PATH,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (sink, argumentIndex) -> "Tainted external input reaches supported filesystem "
                        + "Path argument " + argumentIndex + " of sink rule " + sink.ruleId() + ".");
    }
}
