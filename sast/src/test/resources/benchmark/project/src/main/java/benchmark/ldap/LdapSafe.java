package benchmark.ldap;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.web.bind.annotation.RequestParam;

class LdapSafe {
    private DirContext context;

    void search(@RequestParam String unused, SearchControls controls) throws Exception {
        context.search("", "(objectClass=person)", controls);
    }
}
