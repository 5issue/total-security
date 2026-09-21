package benchmark.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import org.springframework.web.bind.annotation.RequestBody;

class DeserializationVulnerable {
    Object decode(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(body));
        return input.readObject();
    }
}
