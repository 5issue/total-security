package policy.svc05.identifier;

import org.springframework.amqp.rabbit.core.RabbitTemplate;

record IdentifierMessage(Long userId, Long orderId, String eventType) {}

class IdentifierNegative {
    RabbitTemplate rabbitTemplate;

    void publish(Long userId, Long orderId, String eventType) {
        rabbitTemplate.convertAndSend(
                "events", "business.ids", new IdentifierMessage(userId, orderId, eventType));
    }
}
