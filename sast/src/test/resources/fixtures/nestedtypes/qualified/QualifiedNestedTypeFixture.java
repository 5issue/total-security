package fixtures.nestedtypes.qualified;

class QualifiedNestedCaller {
    void call(fixtures.nestedtypes.CartResponseDto.Address address) {
        address.addressId();
    }
}
