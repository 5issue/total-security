package policy.svc05.direct;

import org.springframework.amqp.rabbit.core.RabbitTemplate;

class DirectAccessPositive {
    RabbitTemplate rabbitTemplate;

    void publish(String accessToken) {
        rabbitTemplate.convertAndSend("events", "auth.access", accessToken);
    }
}
