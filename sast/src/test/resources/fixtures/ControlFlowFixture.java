package fixtures.step2b;

import java.util.List;

class ControlFlowFixture {
    String process(List<String> values, boolean ready) {
        String result = "start";

        if (values == null) {
            throw new IllegalArgumentException();
        }

        if (ready) {
            result = normalize(result);
        } else {
            result = "safe";
        }

        int index = 0;
        while (index < values.size()) {
            index = index + 1;
            if (index > 10) {
                break;
            }
            continue;
        }

        for (String value : values) {
            {
                result = value;
            }
        }

        for (int i = 0; i < 1; i = i + 1) {
            result = result + i;
        }

        do {
            result = result.trim();
        } while (result.isEmpty());

        switch (result) {
            case "stop":
                return "early";
            case "skip":
                break;
            default:
                result = "default";
        }

        service.execute(result);
        return result;
    }

    private String normalize(String value) {
        return value;
    }
}
