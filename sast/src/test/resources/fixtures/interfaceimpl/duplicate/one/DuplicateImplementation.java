package fixtures.interfaceimpl.duplicate;

import fixtures.interfaceimpl.DuplicatePort;

class DuplicateImplementation implements DuplicatePort {
    public String process(String input) {
        return input;
    }
}
