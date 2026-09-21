package fixtures.lombokgetter.config.noisprefix;

import lombok.Getter;

@Getter
class ConfigBooleanUser {
    private boolean active;
}

class ConfigBooleanCaller {
    void call(ConfigBooleanUser user) {
        user.isActive();
    }
}
