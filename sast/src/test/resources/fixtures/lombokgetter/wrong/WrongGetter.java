package fixtures.lombokgetter.wrong;

import example.Getter;

@Getter
class WrongUser {
    private String name;
}

class WrongCaller {
    void call(WrongUser user) {
        user.getName();
    }
}
