package com.totalsecurity.sast.detector.command;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** CWE-78 detector over confirmed taint at supported command-execution arguments. */
public final class CommandInjectionDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "OS_COMMAND_INJECTION";
    public static final String VULNERABILITY_TYPE = "OS Command Injection";
    public static final String CWE = "CWE-78";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.COMMAND_EXECUTION,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (sink, argumentIndex) -> "Tainted external input reaches supported operating-system "
                        + "command execution argument " + argumentIndex + " of sink rule "
                        + sink.ruleId() + ".");
    }
}
