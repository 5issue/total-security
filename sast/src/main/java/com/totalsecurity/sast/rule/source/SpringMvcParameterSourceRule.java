package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.ir.AnnotationInfo;
import com.totalsecurity.sast.rule.context.ParameterContext;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class SpringMvcParameterSourceRule implements SourceRule {
    private static final String PACKAGE = "org.springframework.web.bind.annotation.";
    public static final String REQUEST_PARAM_ID = "SPRING_MVC_REQUEST_PARAM";
    public static final String REQUEST_PART_ID = "SPRING_MVC_REQUEST_PART";

    private final String id;
    private final String annotationFqn;

    public SpringMvcParameterSourceRule(String id, String annotationFqn) {
        this.id = Objects.requireNonNull(id, "id");
        this.annotationFqn = Objects.requireNonNull(annotationFqn, "annotationFqn");
    }

    public static List<SourceRule> defaults() {
        return List.of(
                new SpringMvcParameterSourceRule(REQUEST_PARAM_ID, PACKAGE + "RequestParam"),
                new SpringMvcParameterSourceRule(REQUEST_PART_ID, PACKAGE + "RequestPart"),
                new SpringMvcParameterSourceRule("SPRING_MVC_PATH_VARIABLE", PACKAGE + "PathVariable"),
                new SpringMvcParameterSourceRule("SPRING_MVC_REQUEST_BODY", PACKAGE + "RequestBody"),
                new SpringMvcParameterSourceRule("SPRING_MVC_REQUEST_HEADER", PACKAGE + "RequestHeader"),
                new SpringMvcParameterSourceRule("SPRING_MVC_COOKIE_VALUE", PACKAGE + "CookieValue"));
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public Optional<SourceMatch> match(ParameterContext context) {
        return context.parameter().annotations().stream()
                .filter(annotation -> context.types().annotationMatches(annotation.name(), annotationFqn))
                .findFirst()
                .map(annotation -> match(context, annotation));
    }

    private SourceMatch match(ParameterContext context, AnnotationInfo annotation) {
        return new ParameterSourceMatch(
                id,
                context.parameter(),
                "parameter annotation " + annotationFqn + " resolved from " + annotation.name());
    }
}
