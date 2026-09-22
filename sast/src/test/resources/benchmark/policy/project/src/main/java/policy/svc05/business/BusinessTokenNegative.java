package policy.svc05.business;

import org.springframework.amqp.rabbit.core.RabbitTemplate;

class BusinessTokenNegative {
    RabbitTemplate rabbitTemplate;

    void publish(String reservationToken) {
        rabbitTemplate.convertAndSend("events", "business.reservation", reservationToken);
    }
}
