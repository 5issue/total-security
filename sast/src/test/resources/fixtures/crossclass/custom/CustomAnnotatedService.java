package fixtures.crossclass.custom;

import fixtures.crossclass.repository.UserRepository;

@Service
class CustomAnnotatedService {
    private UserRepository repository;

    void sql(String value) throws Exception {
        repository.sql(value);
    }
}
