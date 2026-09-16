package fixtures;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

class LdapInjectionFixture {
    private DirContext context;
    private SearchControls controls;
    private LdapTemplate ldapTemplate;

    void requestParam(@RequestParam String input) {
        String filter = "(uid=" + input + ")";
        context.search("ou=users", filter, controls);
    }

    void pathVariable(@PathVariable String input) {
        context.search("ou=users", input, controls);
    }

    void requestBody(@RequestBody String input) {
        context.search("ou=users", "(mail=" + input + ")", controls);
    }

    void requestHeader(@RequestHeader String input) {
        context.search("ou=users", input, controls);
    }

    void cookieValue(@CookieValue String input) {
        context.search("ou=users", input, controls);
    }

    void servletSource(HttpServletRequest request) {
        String input = request.getParameter("filter");
        context.search("ou=users", input, controls);
    }

    void directBinary(@RequestParam String input) {
        context.search("ou=users", "(cn=" + input + ")", controls);
    }

    void localAssignment(@RequestParam String input) {
        String value = input;
        String filter = value;
        context.search("ou=users", filter, controls);
    }

    void throughTrim(@RequestParam String input) {
        String filter = input.trim();
        context.search("ou=users", filter, controls);
    }

    void branch(@RequestParam String input, boolean selected) {
        String filter;
        if (selected) {
            filter = input;
        } else {
            filter = "(uid=fixed)";
        }
        context.search("ou=users", filter, controls);
    }

    void loop(@RequestParam String input, boolean active) {
        String filter = "(uid=fixed)";
        while (active) {
            filter = input;
            active = false;
        }
        context.search("ou=users", filter, controls);
    }

    void parameterizedFilterExpr(
            @RequestParam String filterExpr, Object[] filterArgs) {
        context.search("ou=users", filterExpr, filterArgs, controls);
    }

    void nameBase(@RequestParam String input, Name base) {
        context.search(base, input, controls);
    }

    void initialDirContext(
            @RequestParam String input, InitialDirContext initialContext) {
        initialContext.search("ou=users", input, controls);
    }

    void ldapContext(@RequestParam String input, LdapContext ldapContext) {
        ldapContext.search("ou=users", input, controls);
    }

    void initialLdapContext(
            @RequestParam String input, InitialLdapContext initialContext) {
        initialContext.search("ou=users", input, controls);
    }

    void fixedFilter() {
        context.search("ou=users", "(uid=fixed)", controls);
    }

    void sourceWithoutSink(@RequestParam String input) {
        consume(input);
    }

    void cleanOverwrite(@RequestParam String input) {
        String filter = input;
        filter = "(uid=fixed)";
        context.search("ou=users", filter, controls);
    }

    void customDirContext(@RequestParam String input, custom.DirContext customContext) {
        customContext.search("ou=users", input, controls);
    }

    void customDirectory(@RequestParam String input, CustomDirectory directory) {
        directory.search("ou=users", input, controls);
    }

    void attributesOverload(@RequestParam String input, Attributes attributes) {
        context.search(input, attributes);
    }

    void parameterizedArgsOnly(@RequestParam Object[] filterArgs) {
        context.search("ou=users", "(uid={0})", filterArgs, controls);
    }

    void taintedBaseOnly(@RequestParam String base) {
        context.search(base, "(uid=fixed)", controls);
    }

    void unknownBuilder(@RequestParam String input) {
        String filter = buildFilter(input);
        context.search("ou=users", filter, controls);
    }

    void ordinaryMethod(@RequestParam String input) {
        consume(input);
    }

    void springLdapTemplate(@RequestParam String input) {
        ldapTemplate.search("ou=users", input, null);
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right) {
        String filter = left + right;
        context.search("ou=users", filter, controls);
    }

    private String buildFilter(String input) {
        return input;
    }

    private void consume(String value) {}
}

class CustomDirectory {
    void search(String base, String filter, SearchControls controls) {}
}
