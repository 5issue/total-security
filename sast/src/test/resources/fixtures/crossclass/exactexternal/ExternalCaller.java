package fixtures.crossclass.exactexternal;

import external.DuplicateService;
import org.springframework.web.bind.annotation.RequestParam;

class ExternalCaller {
    private DuplicateService duplicateService;

    void call(@RequestParam String input) {
        duplicateService.run(input);
    }
}
