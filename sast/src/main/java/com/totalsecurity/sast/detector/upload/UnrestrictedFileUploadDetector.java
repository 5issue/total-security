package com.totalsecurity.sast.detector.upload;

import com.totalsecurity.sast.finding.FileUploadFinding;
import com.totalsecurity.sast.finding.FindingSeverity;
import com.totalsecurity.sast.finding.FindingSink;
import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import com.totalsecurity.sast.rule.source.SpringMultipartOriginalFilenameSourceRule;
import java.util.List;

/** High-confidence CWE-434 detector for direct Spring MultipartFile transfer flows. */
public final class UnrestrictedFileUploadDetector {
    public static final String RULE_ID = "UNRESTRICTED_FILE_UPLOAD";
    public static final String VULNERABILITY_TYPE = "Unrestricted File Upload";
    public static final String CWE = "CWE-434";
    public static final FindingSeverity SEVERITY = FindingSeverity.HIGH;
    public static final String EVIDENCE =
            "An externally supplied multipart file is stored using an attacker-controlled filename/type in a supported file-upload flow.";

    private final SpringMultipartFileUploadAnalyzer analyzer =
            new SpringMultipartFileUploadAnalyzer();

    public List<FileUploadFinding> detect(
            JavaFileInfo file,
            ClassInfo enclosingClass,
            MethodInfo method,
            RuleAwareTaintResult analysis) {
        return analyzer.analyze(file, enclosingClass, method, analysis).stream()
                .filter(upload -> upload.target().control()
                        == FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED)
                .map(UnrestrictedFileUploadDetector::toFinding)
                .toList();
    }

    private static FileUploadFinding toFinding(SupportedFileUpload upload) {
        var sink = upload.sink();
        return new FileUploadFinding(
                RULE_ID,
                VULNERABILITY_TYPE,
                CWE,
                SEVERITY,
                sink.location(),
                SpringMultipartOriginalFilenameSourceRule.MULTIPART_FILE,
                upload.targetType(),
                upload.target().control(),
                new FindingSink(
                        sink.ruleId(),
                        sink.category(),
                        sink.call().call().methodName(),
                        0,
                        sink.location()),
                upload.evidence(),
                EVIDENCE);
    }
}
