package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.source.SpringMultipartOriginalFilenameSourceRule;
import java.util.Optional;
import java.util.Set;

/** Exact destination argument of Spring MultipartFile.transferTo(File|Path). */
public final class SpringMultipartFileTransferSinkRule implements SinkRule {
    public static final String ID = "SPRING_MULTIPART_FILE_TRANSFER";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (context.receiverQualifiedType()
                        .filter(SpringMultipartOriginalFilenameSourceRule.MULTIPART_FILE::equals)
                        .isEmpty()
                || !context.methodName().equals("transferTo")
                || context.argumentCount() != 1
                || !(context.argumentHasType(0, "java.nio.file.Path")
                        || context.argumentHasType(0, "java.io.File"))) {
            return Optional.empty();
        }
        String targetType = context.argumentQualifiedTypes().getFirst().orElseThrow();
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.FILE_UPLOAD_TARGET,
                context.call(),
                Set.of(0),
                context.location(),
                SpringMultipartOriginalFilenameSourceRule.MULTIPART_FILE
                        + ".transferTo(" + targetType + ") destination argument 0"));
    }
}
