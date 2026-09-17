package fixtures;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

class UnrestrictedFileUploadFixture {
    void requestParamPath(@RequestParam MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename();
        Path target = Path.of("/uploads", filename);
        file.transferTo(target);
    }

    void requestPartPath(@RequestPart MultipartFile file) throws IOException {
        file.transferTo(Path.of("/uploads", file.getOriginalFilename()));
    }

    void directPath(@RequestParam MultipartFile file) throws IOException {
        file.transferTo(Path.of("/uploads", file.getOriginalFilename()));
    }

    void localAssignment(@RequestParam MultipartFile file) throws IOException {
        String filename;
        filename = file.getOriginalFilename();
        Path target;
        target = Path.of("/uploads", filename);
        file.transferTo(target);
    }

    void fixedPrefix(@RequestParam MultipartFile file) throws IOException {
        String filename = "prefix-" + file.getOriginalFilename();
        file.transferTo(Path.of("/uploads", filename));
    }

    void externalFilename(
            @RequestParam MultipartFile file,
            @RequestParam String filename) throws IOException {
        file.transferTo(Path.of("/uploads", filename));
    }

    void attackerBranch(
            @RequestParam MultipartFile file,
            boolean useOriginal) throws IOException {
        Path target;
        if (useOriginal) {
            target = Path.of("/uploads", file.getOriginalFilename());
        } else {
            target = Path.of("/uploads/avatar.jpg");
        }
        file.transferTo(target);
    }

    void multipleFilenameOrigins(
            @RequestParam MultipartFile file,
            @RequestParam String left,
            @RequestHeader String right,
            boolean chooseLeft) throws IOException {
        String filename;
        if (chooseLeft) {
            filename = left;
        } else {
            filename = right;
        }
        file.transferTo(Path.of("/uploads", filename));
    }

    void fileTarget(@RequestParam MultipartFile file) throws IOException {
        File target = new File("/uploads", file.getOriginalFilename());
        file.transferTo(target);
    }

    void fileSinglePathname(@RequestParam MultipartFile file) throws IOException {
        File target = new File("/uploads/" + file.getOriginalFilename());
        file.transferTo(target);
    }

    void fileParentChild(@RequestParam MultipartFile file) throws IOException {
        File parent = new File("/uploads");
        File target = new File(parent, file.getOriginalFilename());
        file.transferTo(target);
    }

    void nestedTrailingAttacker(
            @RequestParam MultipartFile file,
            @RequestParam String other) throws IOException {
        String filename = file.getOriginalFilename() + ".jpg" + other;
        file.transferTo(Path.of("/uploads", filename));
    }

    void fixedFilename(@RequestParam MultipartFile file) throws IOException {
        file.transferTo(Path.of("/uploads/avatar.jpg"));
    }

    void originalWithFixedExtension(@RequestParam MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename() + ".jpg";
        file.transferTo(Path.of("/uploads", filename));
    }

    void inputWithFixedExtension(
            @RequestParam MultipartFile file,
            @RequestParam String input) throws IOException {
        file.transferTo(Path.of("/uploads", input + ".png"));
    }

    void splitFixedExtension(
            @RequestParam MultipartFile file,
            @RequestParam String input) throws IOException {
        file.transferTo(Path.of("/uploads", input + "." + "jpg"));
    }

    void sourceWithoutTransfer(@RequestParam MultipartFile file) {
        String filename = file.getOriginalFilename();
    }

    void nonExternalMultipart(MultipartFile file, @RequestParam String input)
            throws IOException {
        file.transferTo(Path.of("/uploads", input));
    }

    void customMultipart(
            @RequestParam CustomTypes.MultipartFile file,
            @RequestParam String input) throws IOException {
        file.transferTo(Path.of("/uploads", input));
    }

    void customTransfer(
            @RequestParam MultipartFile file,
            @RequestParam String input,
            CustomUpload storage) throws IOException {
        storage.transferTo(Path.of("/uploads", input));
    }

    void customOriginalFilename(@RequestParam MultipartFile file, CustomUpload custom)
            throws IOException {
        String filename = custom.getOriginalFilename();
        file.transferTo(Path.of("/uploads", filename));
    }

    void unknownBuilder(@RequestParam MultipartFile file) throws IOException {
        String filename = buildFilename(file.getOriginalFilename());
        file.transferTo(Path.of("/uploads", filename));
    }

    void contentTypeOnly(@RequestParam MultipartFile file) {
        String contentType = file.getContentType();
    }

    void contentTypeDoesNotSanitize(@RequestParam MultipartFile file) throws IOException {
        String contentType = file.getContentType();
        file.transferTo(Path.of("/uploads", file.getOriginalFilename()));
    }

    void customRequestPart(@custom.RequestPart MultipartFile file) throws IOException {
        file.transferTo(Path.of("/uploads", file.getOriginalFilename()));
    }

    void ordinaryFilesWrite(@RequestParam String input) throws IOException {
        Files.writeString(Path.of("/uploads/avatar.jpg"), input);
    }

    void pathTraversalOnly(@RequestParam String input) throws IOException {
        Files.readString(Path.of("/uploads", input));
    }

    void generatedUuidWithFixedExtension(@RequestParam MultipartFile file)
            throws IOException {
        String filename = UUID.randomUUID().toString() + ".jpg";
        file.transferTo(Path.of("/uploads", filename));
    }

    void originalFilenameReadOnly(@RequestParam MultipartFile file) {
        String filename = file.getOriginalFilename();
    }

    void targetOnly(@RequestParam MultipartFile file) {
        Path target = Path.of("/uploads", file.getOriginalFilename());
    }

    void validationNameIsNotAProof(@RequestParam MultipartFile file) throws IOException {
        String filename = validateExtension(file.getOriginalFilename());
        file.transferTo(Path.of("/uploads", filename));
    }

    void fileTargetFixedExtension(@RequestParam MultipartFile file) throws IOException {
        File target = new File("/uploads", file.getOriginalFilename() + ".jpg");
        file.transferTo(target);
    }

    String buildFilename(String input) {
        return input;
    }

    String validateExtension(String input) {
        return input;
    }
}

class CustomTypes {
    static class MultipartFile {
        void transferTo(Path target) {}
    }
}

class CustomUpload {
    void transferTo(Path target) {}

    String getOriginalFilename() {
        return "custom.jpg";
    }
}
