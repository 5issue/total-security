package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Matches selected direct RestTemplate requests whose first argument is a String or URI target. */
public final class SpringRestTemplateNetworkSinkRule implements SinkRule {
    public static final String ID = "SPRING_REST_TEMPLATE_NETWORK_TARGET";
    private static final String RECEIVER = "org.springframework.web.client.RestTemplate";
    private static final Set<String> TARGET_TYPES = Set.of("java.lang.String", "java.net.URI");
    private static final Map<String, Integer> MINIMUM_ARITIES = Map.ofEntries(
            Map.entry("getForObject", 2),
            Map.entry("getForEntity", 2),
            Map.entry("postForObject", 3),
            Map.entry("postForEntity", 3),
            Map.entry("put", 2),
            Map.entry("delete", 1),
            Map.entry("exchange", 4),
            Map.entry("execute", 4),
            Map.entry("headForHeaders", 1),
            Map.entry("optionsForAllow", 1),
            Map.entry("patchForObject", 3));

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        Integer minimumArity = MINIMUM_ARITIES.get(context.methodName());
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || minimumArity == null
                || context.argumentCount() < minimumArity
                || context.argumentQualifiedTypes().getFirst().stream()
                        .noneMatch(TARGET_TYPES::contains)) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.NETWORK_REQUEST_TARGET,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + "." + context.methodName() + " outbound request target argument 0"));
    }
}
