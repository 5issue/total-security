package fixtures.crossclass.duplicate.caller;

import fixtures.crossclass.duplicate.one.*;
import fixtures.crossclass.duplicate.two.*;
import org.springframework.web.bind.annotation.RequestParam;

class AmbiguousCaller {
    private DuplicateService duplicateService;

    void call(@RequestParam String input) {
        duplicateService.run(input);
    }
}
