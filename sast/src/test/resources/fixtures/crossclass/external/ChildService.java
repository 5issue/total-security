package fixtures.crossclass.external;

import fixtures.crossclass.repository.UserRepository;

class ChildService extends BaseService {
    private UserRepository repository;

    void forward(String value) throws Exception {
        repository.sql(value);
    }
}
