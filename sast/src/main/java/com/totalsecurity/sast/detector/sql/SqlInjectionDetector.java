package com.totalsecurity.sast.detector.sql;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** CWE-89 detector over STEP 6 SQL_TEXT sink matches and STEP 5 taint provenance. */
public final class SqlInjectionDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "SQL_INJECTION";
    public static final String VULNERABILITY_TYPE = "SQL Injection";
    public static final String CWE = "CWE-89";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.SQL_TEXT,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (sink, argumentIndex) -> "Tainted external input reaches SQL text argument "
                        + argumentIndex + " of sink rule " + sink.ruleId() + " ("
                        + sink.call().call().methodName()
                        + ") without a modeled safe SQL-text construction.");
    }
}
