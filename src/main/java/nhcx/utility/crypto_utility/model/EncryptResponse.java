package nhcx.utility.crypto_utility.model;

import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
public class EncryptResponse {
    private String encyptedPayload;
    private String corelationID;

}
