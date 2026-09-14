package fixtures.step4;

class DataFlowFixture {
    void chain(String input) {
        String a = input;
        String b = a;
        String c = b;
        execute(c);
    }

    void overwrite(String input) {
        String value = input;
        value = "safe";
        execute(value);
    }

    String binary(String left, String right) {
        String combined = left + right;
        execute(combined);
        return combined;
    }

    void branchMerge(boolean flag, String left, String right) {
        String value;
        if (flag) {
            value = left;
        } else {
            value = right;
        }
        execute(value);
    }

    void ifWithoutElse(boolean flag, String input, String other) {
        String value = input;
        if (flag) {
            value = other;
        }
        execute(value);
    }

    void earlyReturn(boolean stop, String input, String other) {
        String value = input;
        if (stop) {
            return;
        }
        value = other;
        execute(value);
    }

    void whileFlow(boolean active, String input) {
        String value = input;
        while (active) {
            value = next(value);
        }
        execute(value);
    }

    void forFlow(int limit, String input) {
        String value = input;
        for (int i = 0; i < limit; i = i + 1) {
            value = step(value);
        }
        execute(value);
    }

    void unreachable(String input) {
        return;
        String value = input;
        execute(value);
    }

    void noInitializer() {
        String value;
        execute(value);
    }

    void siblingScopes(String left, String right) {
        {
            String value = left;
            consume(value);
        }
        {
            String value = right;
            consume(value);
        }
    }

    void expressionShapes(Worker worker, String input, String suffix) {
        String combined = (input + suffix);
        consume(worker.value);
        Holder holder = new Holder(input);
        worker.execute(combined, holder);
    }

    void unknownExpression(String input) {
        Runnable task = () -> consume(input);
        consume(task);
    }

    void unresolvedReference() {
        execute(missing);
    }
}
