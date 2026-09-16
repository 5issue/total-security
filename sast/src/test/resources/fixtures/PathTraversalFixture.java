package fixtures;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

class PathTraversalFixture {
    void requestParam(@RequestParam String input) {
        Path path = Path.of(input);
        Files.readString(path);
    }

    void pathVariable(@PathVariable String input) {
        Files.readAllBytes(Path.of(input));
    }

    void servletSource(HttpServletRequest request) {
        String input = request.getParameter("file");
        Path path = Paths.get(input);
        Files.newInputStream(path);
    }

    void localAssignment(@RequestParam String input) {
        String fileName = input;
        Path path = Path.of(fileName);
        Files.newBufferedReader(path);
    }

    void directNested(@RequestParam String input) {
        Files.readString(Path.of(input));
    }

    void resolve(@RequestParam String input) {
        Path base = Path.of("/safe/base");
        Path path = base.resolve(input);
        Files.readString(path);
    }

    void normalize(@RequestParam String input) {
        Path path = Path.of(input).normalize();
        Files.readString(path);
    }

    void toAbsolutePath(@RequestParam String input) {
        Path path = Path.of(input).toAbsolutePath();
        Files.readString(path);
    }

    void branch(@RequestParam String input, boolean selected) {
        Path path;
        if (selected) {
            path = Path.of(input);
        } else {
            path = Path.of("/fixed/file.txt");
        }
        Files.readString(path);
    }

    void loop(@RequestParam String input, boolean active) {
        Path path = Path.of("/fixed/file.txt");
        while (active) {
            path = Path.of(input);
            active = false;
        }
        Files.readString(path);
    }

    void writeTaintedPath(@RequestParam String input) {
        Files.writeString(Path.of(input), "clean-content");
    }

    void deleteTaintedPath(@RequestParam String input) {
        Files.delete(Path.of(input));
    }

    void outputStreamTaintedPath(@RequestParam String input) {
        Files.newOutputStream(Path.of(input));
    }

    void deleteIfExistsTaintedPath(@RequestParam String input) {
        Files.deleteIfExists(Path.of(input));
    }

    void fixedPath() {
        Files.readString(Path.of("/fixed/file.txt"));
    }

    void sourceWithoutSink(@RequestParam String input) {
        consumeString(input);
    }

    void cleanOverwrite(@RequestParam String input) {
        Path path = Path.of(input);
        path = Path.of("/fixed/file.txt");
        Files.readString(path);
    }

    void customFiles(@RequestParam String input) {
        custom.Files.readString(Path.of(input));
    }

    void customFilesClass(@RequestParam String input, CustomFiles files) {
        files.readAllBytes(Path.of(input));
    }

    void customPathFactory(@RequestParam String input) {
        Path path = CustomPath.of(input);
        Files.readString(path);
    }

    void unknownPathBuilder(@RequestParam String input) {
        Path path = pathBuilder(input);
        Files.readString(path);
    }

    void taintedContentOnly(@RequestParam String input) {
        Files.writeString(Path.of("/safe/output.txt"), input);
    }

    void ordinaryMethod(@RequestParam String input) {
        Path path = Path.of(input);
        consumePath(path);
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right,
            boolean selected) {
        Path path;
        if (selected) {
            path = Path.of(left);
        } else {
            path = Path.of(right);
        }
        Files.readString(path);
    }

    private Path pathBuilder(String input) {
        return Path.of(input);
    }

    private void consumeString(String value) {}

    private void consumePath(Path value) {}
}

class CustomFiles {
    void readAllBytes(Path path) {}
}

class CustomPath {
    static Path of(String value) {
        return Path.of(value);
    }
}
