package policy.svc05.base64;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

class Base64RoutingPositive {
    RabbitTemplate rabbitTemplate;

    void publish(String accessToken, MessagePostProcessor processor) {
        String encoded = Base64.getEncoder().encodeToString(
                accessToken.getBytes(StandardCharsets.UTF_8));
        rabbitTemplate.convertAndSend("auth.route", encoded, processor);
    }
}
