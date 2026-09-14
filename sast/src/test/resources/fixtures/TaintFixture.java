package fixtures.step5;

class TaintFixture {
    void chain(String input) {
        String a = input;
        String b = a;
        String c = b;
        consume(c);
    }

    void unseeded(String input) {
        consume(input);
    }

    void overwrite(String input) {
        String value = input;
        value = "safe";
        consume(value);
    }

    void binaryTainted(String input) {
        String value = "prefix" + input;
        consume(value);
    }

    void binaryClean() {
        String left = "left";
        String right = "right";
        String value = left + right;
        consume(value);
    }

    void branchMerge(boolean flag, String input) {
        String value;
        if (flag) {
            value = input;
        } else {
            value = "safe";
        }
        consume(value);
    }

    void ifWithoutElse(boolean flag, String input) {
        String value = "safe";
        if (flag) {
            value = input;
        }
        consume(value);
    }

    void whileFlow(boolean active, String input) {
        String value = "safe";
        while (active) {
            value = input;
        }
        consume(value);
    }

    void forFlow(int limit, String input) {
        String value = "safe";
        for (int i = 0; i < limit; i = i + 1) {
            value = input;
        }
        consume(value);
    }

    void callParts(Worker receiver, String input, String clean) {
        receiver.execute(input, clean);
    }

    void earlyReturn(boolean stop, String input) {
        String value = input;
        if (stop) {
            return;
        }
        value = "safe";
        consume(value);
    }

    void unreachable(String input) {
        return;
        String value = input;
        consume(value);
    }

    void unknownExpression(String input) {
        Runnable task = () -> consume(input);
        consume(task);
    }

    void unresolvedReference() {
        consume(missing);
    }

    void arbitraryReturn(String input) {
        String value = transform(input);
        consume(value);
    }

    void multipleSeeds(boolean flag, String left, String right) {
        String value;
        if (flag) {
            value = left;
        } else {
            value = right;
        }
        consume(value);
    }

    void expressionSeed() {
        String value = externalValue();
        consume(value);
    }
}
