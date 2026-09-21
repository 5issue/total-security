package fixtures.lombokgetter.config.importtext;

import lombok.Getter;

@Getter
class ImportTextUser {
    private String name;
}

class ImportTextCaller {
    void call(ImportTextUser user) {
        user.getName();
    }
}
