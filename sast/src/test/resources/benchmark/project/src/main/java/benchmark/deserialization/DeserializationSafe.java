package benchmark.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

class DeserializationSafe {
    Object decode(byte[] internal) throws Exception {
        ObjectInputStream input =
                new ObjectInputStream(new ByteArrayInputStream(internal));
        return input.readObject();
    }
}
