package com.totalsecurity.sast.detector.xxe;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.finding.ConfigurationFinding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/** CWE-611 detector for explicit unsafe settings on supported same-method JAXP DOM flows. */
public final class XxeDetector {
    public static final String RULE_ID = "XXE";
    public static final String VULNERABILITY_TYPE = "XML External Entity (XXE)";
    public static final String CWE = "CWE-611";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;

    private final DomXxeConfigurationAnalyzer analyzer = new DomXxeConfigurationAnalyzer();

    public List<ConfigurationFinding> detect(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            DataFlowResult dataFlow) {
        return analyzer.analyze(file, enclosingClass, method, dataFlow).stream()
                .map(use -> new ConfigurationFinding(
                        RULE_ID,
                        VULNERABILITY_TYPE,
                        CWE,
                        SEVERITY,
                        use.parseLocation(),
                        use.factoryType(),
                        use.parserType(),
                        use.provenConfigurations(),
                        use.parserCreationLocation(),
                        use.parseLocation(),
                        "A supported JAXP DOM parser was created from a DocumentBuilderFactory "
                                + "with fully proven external-resolution path(s): "
                                + use.provenPaths().stream()
                                        .sorted(Comparator.comparing(Enum::name))
                                        .map(Enum::name)
                                        .collect(Collectors.joining(", "))
                                + ". The derived builder was subsequently used to parse XML. "
                                + "Attacker-controlled XML input "
                                + "is not independently established."))
                .toList();
    }
}
