package fixtures.nestedtypes.duplicate;

class DuplicateOuter {
    record Address(Long id) {}
}

class DuplicateNestedCaller {
    void call(DuplicateOuter.Address address) {
        address.id();
    }
}
