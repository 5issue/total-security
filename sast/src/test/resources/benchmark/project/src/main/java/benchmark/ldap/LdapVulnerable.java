package benchmark.ldap;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.web.bind.annotation.RequestParam;

class LdapVulnerable {
    private DirContext context;

    void search(@RequestParam String input, SearchControls controls) throws Exception {
        String filter = "(uid=" + input + ")";
        context.search("", filter, controls);
    }
}
