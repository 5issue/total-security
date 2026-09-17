package fixtures.crossclass.controller;

import fixtures.crossclass.context.ContextService;
import fixtures.crossclass.external.AmbiguousService;
import fixtures.crossclass.external.BaseService;
import fixtures.crossclass.external.IntService;
import fixtures.crossclass.external.OverloadService;
import fixtures.crossclass.external.UserPort;
import fixtures.crossclass.outbound.OutboundGateway;
import fixtures.crossclass.repository.SpringDataRepository;
import fixtures.crossclass.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Statement;
import java.time.Clock;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
class UserController {
    private final UserService userService;
    @Autowired private OutboundGateway outboundGateway;
    private Statement statement;
    private Object service;
    private Object customAnnotatedService;
    private Clock externalService;
    private UserPort userPort;
    private BaseService baseService;
    private OverloadService overloadService;
    private IntService intService;
    private AmbiguousService ambiguousService;
    private SpringDataRepository springDataRepository;
    private ContextService contextService;

    UserController(UserService userService) {
        this.userService = userService;
    }

    void sql(@RequestParam String input) throws Exception {
        userService.sql(input);
    }

    void command(@PathVariable String input) throws Exception {
        userService.command(input);
    }

    void path(@RequestParam String input) throws Exception {
        userService.path(input);
    }

    void ssrf(@RequestParam String input) {
        outboundGateway.request(input);
    }

    void ldap(@RequestHeader String input) throws Exception {
        userService.ldap(input);
    }

    void mixed(@RequestParam String input) throws Exception {
        privateHelper(input);
    }

    void privateHelper(String value) throws Exception {
        userService.mixed(value);
    }

    void returned(@RequestParam String input) throws Exception {
        String sql = userService.buildSql(input);
        statement.executeQuery(sql);
    }

    void parameterReceiver(@RequestParam String input, UserService serviceParameter)
            throws Exception {
        serviceParameter.sql(input);
    }

    void localReceiver(@RequestParam String input) throws Exception {
        UserService local = userService;
        local.sql(input);
    }

    void multipleOrigins(
            @RequestParam String left,
            @RequestHeader String right,
            boolean chooseLeft) throws Exception {
        String value;
        if (chooseLeft) {
            value = left;
        } else {
            value = right;
        }
        userService.sql(value);
    }

    void clean() throws Exception {
        userService.sql("SELECT 1");
    }

    void overwritten(@RequestParam String input) throws Exception {
        input = "SELECT 1";
        userService.sql(input);
    }

    void objectReceiver(@RequestParam String input) throws Exception {
        service.sql(input);
    }

    void externalReceiver(@RequestParam String input) throws Exception {
        externalService.sql(input);
    }

    void customAnnotationOnly(@RequestParam String input) throws Exception {
        customAnnotatedService.sql(input);
    }

    void interfaceReceiver(@RequestParam String input) throws Exception {
        userPort.sql(input);
    }

    void inheritedReceiver(@RequestParam String input) throws Exception {
        baseService.forward(input);
    }

    void overload(@RequestParam String input) throws Exception {
        overloadService.route(input);
    }

    void incompatible(@RequestParam String input) {
        intService.route(input);
    }

    void ambiguous(@RequestParam String input) throws Exception {
        ambiguousService.route(externalService.toString());
    }

    void springData(@RequestParam String input) {
        springDataRepository.findById(input);
    }

    void xss(@RequestParam String input, HttpServletResponse response) throws Exception {
        contextService.xss(input, response);
    }

    void redirect(@RequestParam String input, HttpServletResponse response) throws Exception {
        contextService.redirect(input, response);
    }

    void upload(@RequestParam MultipartFile file, @RequestParam String name) throws Exception {
        contextService.upload(file, name);
    }

    void xxe(@RequestParam java.io.InputStream input, DocumentBuilderFactory factory)
            throws Exception {
        contextService.xxe(input, factory);
    }
}
