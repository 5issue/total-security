package fixtures.crossclass.service;

import fixtures.crossclass.repository.UserRepository;

class SamePackageHelper {
    void forward(String value, UserRepository repository) throws Exception {
        repository.sql(value);
    }
}
