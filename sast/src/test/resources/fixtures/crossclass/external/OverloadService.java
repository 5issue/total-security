package fixtures.crossclass.external;

import fixtures.crossclass.repository.UserRepository;

class OverloadService {
    private UserRepository repository;

    void route(String value) throws Exception {
        repository.sql(value);
    }

    void route(int value) {}
}
