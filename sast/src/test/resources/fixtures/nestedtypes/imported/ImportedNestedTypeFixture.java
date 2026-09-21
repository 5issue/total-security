package fixtures.nestedtypes.imported;

import fixtures.nestedtypes.CartResponseDto.Address;

class ImportedNestedCaller {
    void call(Address address) {
        address.addressId();
    }
}
