package benchmark.path;

import java.nio.file.Files;
import java.nio.file.Path;

class PathConstantSafe {
    String read() throws Exception {
        return Files.readString(Path.of("/srv/app/config.json"));
    }
}
