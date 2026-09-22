package fixtures.svc05.backendderived;

import org.springframework.amqp.rabbit.core.RabbitTemplate;

class BackendDerivedOrderPublisher {
    RabbitTemplate rabbitTemplate;

    void publishOrder(Long orderId, Long memberId, String reservationToken) {
        rabbitTemplate.convertAndSend(
                "order.topic.exchange",
                "order.inventory.confirm",
                new OrderEvent(orderId, memberId, reservationToken));
    }
}

record OrderEvent(Long orderId, Long memberId, String reservationToken) {}
