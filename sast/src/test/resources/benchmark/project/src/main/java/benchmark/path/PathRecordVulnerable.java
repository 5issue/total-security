package benchmark.path;

import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.RequestBody;

record PathRequest(String path) {}

class PathRecordVulnerable {
    String read(@RequestBody PathRequest request) throws Exception {
        return Files.readString(Path.of(request.path()));
    }
}
