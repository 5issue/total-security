package fixtures.lombokgetter.config.importdefault;

import lombok.Getter;

@Getter
class ImportDefaultUser {
    private String name;
}

class ImportDefaultCaller {
    void call(ImportDefaultUser user) {
        user.getName();
    }
}
