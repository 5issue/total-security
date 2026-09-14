package fixtures.step3;

import java.util.List;

class CfgFixture {
    void sequential() {
        int a = 1;
        int b = 2;
        service.execute(a);
    }

    int ifWithoutElse(boolean flag) {
        int value = 0;
        if (flag) {
            value = 1;
        }
        return value;
    }

    int branches(boolean first, boolean second) {
        if (first) {
            if (second) {
                return 1;
            }
            return 2;
        } else {
            return 3;
        }
    }

    int earlyReturn(boolean flag) {
        if (flag) {
            return 1;
        }
        work();
        return 2;
    }

    void whileFlow(boolean active) {
        while (active) {
            if (stop()) {
                break;
            }
            if (skip()) {
                continue;
            }
            work();
        }
        after();
    }

    void forFlow() {
        for (int i = 0; i < 3; i = i + 1) {
            if (skip(i)) {
                continue;
            }
            work(i);
        }
        after();
    }

    void forWithoutUpdate(boolean active) {
        for (int i = 0; active;) {
            if (skip(i)) {
                continue;
            }
            work(i);
        }
        after();
    }

    void doFlow() {
        do {
            work();
        } while (active());
        after();
    }

    void enhancedFlow(List<String> values) {
        for (String value : values) {
            work(value);
        }
        after();
    }

    int switchFlow(int value) {
        switch (value) {
            case 1:
                first();
            case 2:
                second();
                break;
            default:
                other();
        }
        return value;
    }

    void nestedLoopSwitch(boolean active, int value) {
        while (active) {
            switch (value) {
                case 1:
                    break;
                default:
                    work();
            }
            continue;
        }
        after();
    }

    void throwing() {
        throw new IllegalStateException();
        after();
    }

    void unknownFlow() {
        synchronized (this) {
            work();
        }
        after();
    }
}
