package fixtures.lombokgetter.config.importarchive;

import lombok.Getter;

@Getter
class ImportArchiveUser {
    private String name;
}

class ImportArchiveCaller {
    void call(ImportArchiveUser user) {
        user.getName();
    }
}
