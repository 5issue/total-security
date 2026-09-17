package fixtures;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

class InsecureDeserializationFixture {
    Object requestBody(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        return input.readObject();
    }

    Object directNested(@RequestBody byte[] body) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(body)).readObject();
    }

    Object localByteArrayInputStream(@RequestBody byte[] body) throws Exception {
        ByteArrayInputStream bytes = new ByteArrayInputStream(body);
        ObjectInputStream input = new ObjectInputStream(bytes);
        return input.readObject();
    }

    Object inputStreamSupertype(@RequestBody byte[] body) throws Exception {
        InputStream bytes = new ByteArrayInputStream(body);
        ObjectInputStream input = new ObjectInputStream(bytes);
        return input.readObject();
    }

    Object buffered(@RequestBody byte[] body) throws Exception {
        InputStream buffered =
                new BufferedInputStream(new ByteArrayInputStream(body));
        ObjectInputStream input = new ObjectInputStream(buffered);
        return input.readObject();
    }

    Object bufferedWithSize(@RequestBody byte[] body) throws Exception {
        InputStream buffered =
                new BufferedInputStream(new ByteArrayInputStream(body), 8192);
        ObjectInputStream input = new ObjectInputStream(buffered);
        return input.readObject();
    }

    Object localByteAssignment(@RequestBody byte[] body) throws Exception {
        byte[] copy = body;
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(copy));
        return input.readObject();
    }

    Object servletInputStream(HttpServletRequest request) throws Exception {
        ObjectInputStream input = new ObjectInputStream(request.getInputStream());
        return input.readObject();
    }

    Object branch(
            @RequestBody byte[] body,
            byte[] internal,
            boolean selected) throws Exception {
        InputStream bytes;
        if (selected) {
            bytes = new ByteArrayInputStream(body);
        } else {
            bytes = new ByteArrayInputStream(internal);
        }
        ObjectInputStream input = new ObjectInputStream(bytes);
        return input.readObject();
    }

    Object loopWrapper(@RequestBody byte[] body, boolean active) throws Exception {
        InputStream bytes = new ByteArrayInputStream(body);
        while (active) {
            bytes = new BufferedInputStream(bytes);
            active = false;
        }
        ObjectInputStream input = new ObjectInputStream(bytes);
        return input.readObject();
    }

    Object multipleSources(
            @RequestBody byte[] body,
            @RequestHeader byte[] header,
            boolean selected) throws Exception {
        byte[] selectedBytes;
        if (selected) {
            selectedBytes = body;
        } else {
            selectedBytes = header;
        }
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(selectedBytes));
        return input.readObject();
    }

    Object objectStreamAlias(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        ObjectInputStream alias = input;
        return alias.readObject();
    }

    Object filterNotAssumedSafe(
            @RequestBody byte[] body,
            ObjectInputFilter filter) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        input.setObjectInputFilter(filter);
        return input.readObject();
    }

    Object cleanInput(byte[] internal) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(internal));
        return input.readObject();
    }

    void sourceWithoutReadObject(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        input.available();
    }

    void objectStreamCreationOnly(@RequestBody byte[] body) throws Exception {
        new ObjectInputStream(new ByteArrayInputStream(body));
    }

    Object readUnsharedOnly(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        return input.readUnshared();
    }

    Object customObjectInputStream(
            @RequestBody byte[] body,
            custom.ObjectInputStream input) throws Exception {
        return input.readObject();
    }

    Object customReadObject(@RequestBody byte[] body, CustomDeserializer custom) {
        return custom.readObject(body);
    }

    Object arbitraryDeserialize(@RequestBody byte[] body, CustomDeserializer custom) {
        return custom.deserialize(body);
    }

    Object unknownStreamBuilder(@RequestBody byte[] body) throws Exception {
        InputStream stream = buildStream(body);
        ObjectInputStream input = new ObjectInputStream(stream);
        return input.readObject();
    }

    Object jackson(@RequestBody byte[] body, ObjectMapper mapper) throws Exception {
        return mapper.readValue(body, Object.class);
    }

    String dataInput(@RequestBody byte[] body) throws Exception {
        DataInputStream input =
                new DataInputStream(new ByteArrayInputStream(body));
        return input.readUTF();
    }

    Object unknownReceiver(
            @RequestBody byte[] body,
            ObjectInputStream unknown) throws Exception {
        ObjectInputStream known =
                new ObjectInputStream(new ByteArrayInputStream(body));
        return unknown.readObject();
    }

    Object cleanOverwrite(
            @RequestBody byte[] body,
            byte[] internal) throws Exception {
        byte[] selected = body;
        selected = internal;
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(selected));
        return input.readObject();
    }

    Object customRequest(
            CustomRequest request,
            ObjectInputStream unknown) throws Exception {
        InputStream stream = request.getInputStream();
        return unknown.readObject();
    }

    private InputStream buildStream(byte[] body) {
        return new ByteArrayInputStream(body);
    }
}

class CustomDeserializer {
    Object readObject(byte[] body) {
        return body;
    }

    Object deserialize(byte[] body) {
        return body;
    }
}

class CustomRequest {
    InputStream getInputStream() {
        return null;
    }
}
