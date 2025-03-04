
package nhcx.utility.crypto_utility.model;

import java.util.HashMap;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DecryptResponse {
    private String body;
    private HashMap<String, Object> header;
}
