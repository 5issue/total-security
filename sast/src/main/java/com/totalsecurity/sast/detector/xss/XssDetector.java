package com.totalsecurity.sast.detector.xss;

import com.totalsecurity.sast.detector.TaintSinkFindingFactory;
import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.XssFinding;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CWE-79 detector for proven Jakarta servlet HTML response-writer contexts. */
public final class XssDetector {
    public static final String RULE_ID = "XSS";
    public static final String VULNERABILITY_TYPE = "Cross-Site Scripting (XSS)";
    public static final String CWE = "CWE-79";
    public static final FindingSeverity SEVERITY = FindingSeverity.MEDIUM;
    public static final String EVIDENCE =
            "Tainted external input is written raw to a supported HTML response body.";

    private final ServletHtmlResponseAnalyzer analyzer = new ServletHtmlResponseAnalyzer();

    public List<XssFinding> detect(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        Map<OutputKey, HtmlResponseOutput> outputs = new LinkedHashMap<>();
        analyzer.analyze(file, enclosingClass, method, analysis).forEach(output -> outputs.put(
                new OutputKey(output.sink().location(), output.argumentIndex()), output));
        List<Finding> baseFindings = TaintSinkFindingFactory.create(
                analysis,
                SinkCategory.HTTP_RESPONSE_BODY,
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                (ignored, sink, argumentIndex) -> {
                    HtmlResponseOutput output =
                            outputs.get(new OutputKey(sink.location(), argumentIndex));
                    return output != null && output.confirmed();
                },
                (sink, argumentIndex) -> EVIDENCE);
        return baseFindings.stream()
                .map(finding -> toXssFinding(
                        finding,
                        outputs.get(new OutputKey(
                                finding.sink().location(), finding.sink().argumentIndex()))))
                .toList();
    }

    private static XssFinding toXssFinding(
            Finding finding, HtmlResponseOutput output) {
        if (output == null || !output.confirmed()) {
            throw new IllegalStateException("Base XSS finding has no confirmed HTML output proof");
        }
        return new XssFinding(
                finding.ruleId(),
                finding.vulnerabilityType(),
                finding.cwe(),
                finding.severity(),
                finding.primaryLocation(),
                finding.sources(),
                finding.sink(),
                finding.flows(),
                ServletHtmlResponseAnalyzer.RESPONSE_TYPE,
                output.evidence(),
                output.sink().location(),
                finding.evidence());
    }

    private record OutputKey(SourceLocation location, int argumentIndex) {}
}
