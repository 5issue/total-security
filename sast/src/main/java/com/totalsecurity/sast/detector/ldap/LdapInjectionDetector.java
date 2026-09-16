package com.totalsecurity.sast.detector.ldap;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.detector.VulnerabilityDetector;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;

/** CWE-90 detector over confirmed taint at supported JNDI LDAP filter arguments. */
public final class LdapInjectionDetector implements VulnerabilityDetector {
    public static final String RULE_ID = "LDAP_INJECTION";
    public static final String VULNERABILITY_TYPE = "LDAP Injection";
    public static final String CWE = "CWE-90";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    @Override
    public List<Finding> detect(RuleAwareTaintResult analysis) {
        return TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.LDAP_FILTER,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (sink, argumentIndex) -> "Tainted external input reaches a supported LDAP "
                        + "search-filter argument " + argumentIndex + " of sink rule "
                        + sink.ruleId() + ".");
    }
}
