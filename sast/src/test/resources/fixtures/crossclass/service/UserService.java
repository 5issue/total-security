package fixtures.crossclass.service;

import fixtures.crossclass.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
class UserService {
    private final UserRepository repository;
    private SamePackageHelper samePackageHelper;

    UserService(UserRepository repository) {
        this.repository = repository;
    }

    void sql(String value) throws Exception {
        privateSql(value);
    }

    void privateSql(String value) throws Exception {
        repository.sql(value);
    }

    void command(String value) throws Exception {
        repository.command(value);
    }

    void path(String value) throws Exception {
        repository.path(value);
    }

    void ldap(String value) throws Exception {
        repository.ldap(value);
    }

    void mixed(String value) throws Exception {
        samePackageHelper.forward(value, repository);
    }

    String buildSql(String value) {
        return repository.decorate(value);
    }
}
