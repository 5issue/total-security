package fixtures.crossclass.external;

import fixtures.crossclass.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
class UserPortImpl implements UserPort {
    private UserRepository repository;

    public void sql(String value) throws Exception {
        repository.sql(value);
    }
}
