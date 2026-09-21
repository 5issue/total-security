package fixtures.lombokgetter.config.fluent;

import lombok.Getter;

@Getter
class ConfigFluentUser {
    private String name;
}

class ConfigFluentCaller {
    void call(ConfigFluentUser user) {
        user.getName();
    }
}
