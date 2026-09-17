package fixtures.crossclass.external;

import fixtures.crossclass.repository.UserRepository;

class AmbiguousService {
    private UserRepository repository;

    void route(String value) throws Exception {
        repository.sql(value);
    }

    void route(Object value) {}
}
