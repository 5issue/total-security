package com.totalsecurity.sast.detector.xss;

import com.totalsecurity.sast.finding.XssEvidence;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import java.util.List;
import java.util.Objects;

/** Context proof attached to one HTTP_RESPONSE_BODY sink occurrence. */
public record HtmlResponseOutput(
        SinkMatch sink,
        int argumentIndex,
        boolean writerLineageConfirmed,
        HttpResponseContentType contentType,
        HtmlOutputSafety outputSafety,
        List<XssEvidence> evidence) {
    public HtmlResponseOutput {
        Objects.requireNonNull(sink, "sink");
        if (!sink.sensitiveArgumentIndexes().contains(argumentIndex)) {
            throw new IllegalArgumentException("argumentIndex must be sensitive for the sink");
        }
        Objects.requireNonNull(contentType, "contentType");
        Objects.requireNonNull(outputSafety, "outputSafety");
        evidence = List.copyOf(evidence);
    }

    public boolean confirmed() {
        return writerLineageConfirmed
                && contentType == HttpResponseContentType.HTML
                && outputSafety == HtmlOutputSafety.RAW_TAINTED;
    }
}
