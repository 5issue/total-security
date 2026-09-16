package com.totalsecurity.sast.pattern;

import com.totalsecurity.sast.finding.PatternFinding;
import com.totalsecurity.sast.ir.JavaFileInfo;
import java.util.List;

/** A Tree-sitter-independent structural pattern detector over Java IR. */
public interface PatternDetector {
    List<PatternFinding> detect(JavaFileInfo file);
}
