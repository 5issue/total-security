package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

/** Matches supported JNDI directory searches whose argument 1 is an LDAP filter String. */
public final class JndiLdapFilterSinkRule implements SinkRule {
    public static final String ID = "JNDI_LDAP_SEARCH_FILTER";
    private static final Set<String> RECEIVERS = Set.of(
            "javax.naming.directory.DirContext",
            "javax.naming.directory.InitialDirContext",
            "javax.naming.ldap.LdapContext",
            "javax.naming.ldap.InitialLdapContext");
    private static final Set<String> BASE_NAME_TYPES =
            Set.of("java.lang.String", "javax.naming.Name");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (context.receiverQualifiedType().stream().noneMatch(RECEIVERS::contains)
                || !context.methodName().equals("search")
                || !supportedSignature(context)) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.LDAP_FILTER,
                context.call(),
                Set.of(1),
                context.location(),
                context.receiverQualifiedType().orElseThrow()
                        + ".search LDAP filter argument 1"));
    }

    private boolean supportedSignature(CallSiteContext context) {
        if (context.argumentCount() != 3 && context.argumentCount() != 4) {
            return false;
        }
        if (context.argumentQualifiedTypes().get(0).stream().noneMatch(BASE_NAME_TYPES::contains)
                || !context.argumentHasType(1, "java.lang.String")) {
            return false;
        }
        if (context.argumentCount() == 3) {
            return context.argumentHasType(2, "javax.naming.directory.SearchControls");
        }
        return context.argumentHasType(2, "java.lang.Object[]")
                && context.argumentHasType(3, "javax.naming.directory.SearchControls");
    }
}
