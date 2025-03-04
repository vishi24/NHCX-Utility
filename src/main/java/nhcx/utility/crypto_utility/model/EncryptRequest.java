package nhcx.utility.crypto_utility.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EncryptRequest {
    private String resourceType;
    private String sender;
    private String receiver;
}
