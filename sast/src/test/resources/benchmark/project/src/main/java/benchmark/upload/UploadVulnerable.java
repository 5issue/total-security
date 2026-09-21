package benchmark.upload;

import java.nio.file.Path;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

class UploadVulnerable {
    void upload(@RequestParam MultipartFile file) throws Exception {
        file.transferTo(Path.of("/uploads", file.getOriginalFilename()));
    }
}
