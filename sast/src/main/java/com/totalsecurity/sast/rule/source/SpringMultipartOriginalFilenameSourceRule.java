package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;

/** Exact attacker-controlled original filename returned by a Spring multipart upload. */
public final class SpringMultipartOriginalFilenameSourceRule implements SourceRule {
    public static final String ID = "SPRING_MULTIPART_ORIGINAL_FILENAME";
    public static final String MULTIPART_FILE =
            "org.springframework.web.multipart.MultipartFile";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SourceMatch> match(CallSiteContext context) {
        if (context.receiverQualifiedType().filter(MULTIPART_FILE::equals).isEmpty()
                || !context.methodName().equals("getOriginalFilename")
                || context.argumentCount() != 0) {
            return Optional.empty();
        }
        return Optional.of(new ExpressionSourceMatch(
                ID,
                context.call(),
                MULTIPART_FILE + ".getOriginalFilename() external filename value"));
    }
}
