package fixtures.nestedtypes;

import java.sql.Statement;
import fixtures.nestedtypes.shadow.Address;
import org.springframework.web.bind.annotation.RequestBody;

class CartResponseDto {
    record Address(Long addressId, String address) {}

    Long sameEnclosing(Address address) {
        return address.addressId();
    }
}

class ProductSpec {
    enum StorageType {
        ROOM,
        COLD;

        boolean enabled() {
            return true;
        }
    }
}

class A {
    record Result(String value) {}
}

class B {
    record Result(Long value) {}
}

class ExplicitOuter {
    record Address(String value) {
        public String value() {
            return "custom";
        }
    }
}

class DeepOuter {
    static class Middle {
        record Hidden(String value) {}
    }
}

class ImportCollisionOuter {
    record Address(Long id) {}

    void flow(Address value) {
        value.id();
    }
}

class JavaLangCollisionOuter {
    record String(Long id) {}

    void flow(String value) {
        value.id();
    }
}

class NestedService {
    private Statement statement;

    void acceptLong(Long value) {}

    void acceptStorage(ProductSpec.StorageType value) {}

    void acceptString(String value) {}

    void acceptBoolean(boolean value) {}

    void query(String sql) throws Exception {
        statement.executeQuery(sql);
    }
}

class NestedController {
    private NestedService service;

    void recordAccessor(CartResponseDto.Address address) {
        service.acceptLong(address.addressId());
    }

    void enumConstant() {
        service.acceptBoolean(ProductSpec.StorageType.ROOM.enabled());
    }

    void sameSimple(A.Result left, B.Result right) {
        service.acceptString(left.value());
        service.acceptLong(right.value());
    }

    void typeReceiver() {
        CartResponseDto.Address.addressId();
    }

    void explicit(@RequestBody ExplicitOuter.Address address) {
        service.acceptString(address.value());
    }

    void tainted(@RequestBody CartResponseDto.Address address) throws Exception {
        service.query(address.address());
    }

    void enumCompilerMethods(ProductSpec.StorageType storage) {
        ProductSpec.StorageType.values();
        storage.name();
    }
}
