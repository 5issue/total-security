package fixtures.crossclass.repository;

import org.springframework.stereotype.Repository;

@Repository
interface SpringDataRepository {
    Object findById(String id);
}
