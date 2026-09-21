package fixtures.lombokgetter.config.prefix;

import lombok.Getter;

@Getter
class ConfigPrefixUser {
    private String _name;
}

class ConfigPrefixCaller {
    void call(ConfigPrefixUser user) {
        user.get_name();
    }
}
