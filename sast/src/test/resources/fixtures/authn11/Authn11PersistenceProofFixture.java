package fixtures.authn11.persistence;

import jakarta.persistence.Entity;
import lombok.Builder;
import org.springframework.data.jpa.repository.JpaRepository;

@interface Transient {
}

@Entity
class AssignedRefreshTokenEntity {
    String token;

    AssignedRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface AssignedRefreshTokenRepository {
    <S extends AssignedRefreshTokenEntity> S save(S entity);
}

interface AssignedRefreshTokenJpaRepository
        extends JpaRepository<AssignedRefreshTokenEntity, Long>, AssignedRefreshTokenRepository {
}

@Entity
class DiscardedRefreshTokenEntity {
    String token;

    DiscardedRefreshTokenEntity(String token) {
        this.token = "safe";
    }
}

interface DiscardedRefreshTokenRepository {
    <S extends DiscardedRefreshTokenEntity> S save(S entity);
}

interface DiscardedRefreshTokenJpaRepository
        extends JpaRepository<DiscardedRefreshTokenEntity, Long>, DiscardedRefreshTokenRepository {
}

@Entity
class OverwrittenRefreshTokenEntity {
    String token;

    OverwrittenRefreshTokenEntity(String token) {
        this.token = token;
        this.token = "safe";
    }
}

interface OverwrittenRefreshTokenRepository {
    <S extends OverwrittenRefreshTokenEntity> S save(S entity);
}

interface OverwrittenRefreshTokenJpaRepository
        extends JpaRepository<OverwrittenRefreshTokenEntity, Long>, OverwrittenRefreshTokenRepository {
}

@Entity
class UnassignedRefreshTokenEntity {
    String token;

    UnassignedRefreshTokenEntity(String token) {
    }
}

interface UnassignedRefreshTokenRepository {
    <S extends UnassignedRefreshTokenEntity> S save(S entity);
}

interface UnassignedRefreshTokenJpaRepository
        extends JpaRepository<UnassignedRefreshTokenEntity, Long>, UnassignedRefreshTokenRepository {
}

@Entity
class FakeBuilderRefreshTokenEntity {
    String token;

    FakeBuilderRefreshTokenEntity(String token) {
        this.token = token;
    }

    static FakeBuilder builder() {
        return new FakeBuilder();
    }

    static class FakeBuilder {
        FakeBuilder token(String token) {
            return this;
        }

        FakeBuilderRefreshTokenEntity build() {
            return new FakeBuilderRefreshTokenEntity("safe");
        }
    }
}

interface FakeBuilderRefreshTokenRepository {
    <S extends FakeBuilderRefreshTokenEntity> S save(S entity);
}

interface FakeBuilderRefreshTokenJpaRepository
        extends JpaRepository<FakeBuilderRefreshTokenEntity, Long>, FakeBuilderRefreshTokenRepository {
}

@Entity
class StaticRefreshTokenEntity {
    static String token;

    @Builder
    StaticRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface StaticRefreshTokenRepository {
    <S extends StaticRefreshTokenEntity> S save(S entity);
}

interface StaticRefreshTokenJpaRepository
        extends JpaRepository<StaticRefreshTokenEntity, Long>, StaticRefreshTokenRepository {
}

@Entity
class JpaTransientRefreshTokenEntity {
    @jakarta.persistence.Transient
    String token;

    @Builder
    JpaTransientRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface JpaTransientRefreshTokenRepository {
    <S extends JpaTransientRefreshTokenEntity> S save(S entity);
}

interface JpaTransientRefreshTokenJpaRepository
        extends JpaRepository<JpaTransientRefreshTokenEntity, Long>, JpaTransientRefreshTokenRepository {
}

@Entity
class JavaTransientRefreshTokenEntity {
    transient String token;

    @Builder
    JavaTransientRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface JavaTransientRefreshTokenRepository {
    <S extends JavaTransientRefreshTokenEntity> S save(S entity);
}

interface JavaTransientRefreshTokenJpaRepository
        extends JpaRepository<JavaTransientRefreshTokenEntity, Long>, JavaTransientRefreshTokenRepository {
}

@Entity
class CustomTransientRefreshTokenEntity {
    @Transient
    String token;

    @Builder
    CustomTransientRefreshTokenEntity(String token) {
        this.token = token;
    }
}

interface CustomTransientRefreshTokenRepository {
    <S extends CustomTransientRefreshTokenEntity> S save(S entity);
}

interface CustomTransientRefreshTokenJpaRepository
        extends JpaRepository<CustomTransientRefreshTokenEntity, Long>, CustomTransientRefreshTokenRepository {
}

class PersistenceProofService {
    AssignedRefreshTokenRepository assigned;
    DiscardedRefreshTokenRepository discarded;
    OverwrittenRefreshTokenRepository overwritten;
    UnassignedRefreshTokenRepository unassigned;
    FakeBuilderRefreshTokenRepository fakeBuilder;
    StaticRefreshTokenRepository staticField;
    JpaTransientRefreshTokenRepository jpaTransient;
    JavaTransientRefreshTokenRepository javaTransient;
    CustomTransientRefreshTokenRepository customTransient;

    void assignedConstructor(String refreshToken) {
        assigned.save(new AssignedRefreshTokenEntity(refreshToken));
    }

    void discardedConstructor(String refreshToken) {
        discarded.save(new DiscardedRefreshTokenEntity(refreshToken));
    }

    void overwrittenConstructor(String refreshToken) {
        overwritten.save(new OverwrittenRefreshTokenEntity(refreshToken));
    }

    void unassignedConstructor(String refreshToken) {
        unassigned.save(new UnassignedRefreshTokenEntity(refreshToken));
    }

    void fakeBuilder(String refreshToken) {
        fakeBuilder.save(FakeBuilderRefreshTokenEntity.builder()
                .token(refreshToken)
                .build());
    }

    void staticField(String refreshToken) {
        staticField.save(StaticRefreshTokenEntity.builder().token(refreshToken).build());
    }

    void jpaTransientField(String refreshToken) {
        jpaTransient.save(JpaTransientRefreshTokenEntity.builder().token(refreshToken).build());
    }

    void javaTransientField(String refreshToken) {
        javaTransient.save(JavaTransientRefreshTokenEntity.builder().token(refreshToken).build());
    }

    void customTransientField(String refreshToken) {
        customTransient.save(CustomTransientRefreshTokenEntity.builder().token(refreshToken).build());
    }
}
