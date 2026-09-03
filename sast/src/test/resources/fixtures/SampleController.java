package fixtures;

@RestController
public class SampleController {
    public String greet(String name) {
        String message = "Hello, ";
        message = message.concat(name);
        System.out.println(message);
        return message;
    }
}

