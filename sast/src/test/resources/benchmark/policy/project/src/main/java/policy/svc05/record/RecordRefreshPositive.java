package policy.svc05.record;

import org.springframework.amqp.rabbit.core.RabbitTemplate;

record RefreshMessage(Long userId, String refreshToken) {}

class RecordRefreshPositive {
    RabbitTemplate rabbitTemplate;

    void publish(Long userId, String refreshToken) {
        rabbitTemplate.convertAndSend(
                "events", "auth.refresh", new RefreshMessage(userId, refreshToken));
    }
}
