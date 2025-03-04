package nhcx.utility.crypto_utility.service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;

import nhcx.utility.crypto_utility.model.DecryptResponse;
import nhcx.utility.crypto_utility.model.EncryptRequest;
import nhcx.utility.crypto_utility.model.EncryptResponse;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
@PropertySource("classpath:application.properties")
public class ProcessRequest {

    @Autowired
    KeyProcessor keyProcessor;
    @Autowired
    Session session;
    @Autowired
    EncryptResponse encryptResponse;

    DecryptResponse decryptResponse;

    @Value("classpath:private_key.pem")
    private Resource privateKeyResource;

    public DecryptResponse decryptRequest(String encryptedObject) {

        try {

            if (!privateKeyResource.exists()) {
                throw new RuntimeException("Private key file not found in resources folder");
            }

            // Read file content as String and pass to the method
            PrivateKey privateKey = keyProcessor
                    .getRSAPrivateKeyFromPem(privateKeyResource.getFile().toPath().toString());

            decryptResponse = keyProcessor.decryptRequest(privateKey, encryptedObject);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptResponse;
    }

    public EncryptResponse encryptRequest(EncryptRequest request) {

        String encryptedObject = "";
        String sender_code = request.getSender();
        String recipient_code = request.getReceiver();
        ZonedDateTime now = ZonedDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ");
        String timestamp = now.format(formatter);
        UUID coorelation_ID = UUID.randomUUID();

        try {
            // Read payload from file
            String payload = "";
            if ("InsurancePlanRequest".equals(request.getResourceType())) {
                payload = new String(
                        Files.readAllBytes(Paths
                                .get("src/main/java/nhcx/utility/crypto_utility/sample/InsurancePlanRequest.txt")));
            } else if ("PreAuthProvider".equals(request.getResourceType())) {
                payload = new String(
                        Files.readAllBytes(Paths
                                .get("src/main/java/nhcx/utility/crypto_utility/sample/PreAuth.txt")));
            } else if ("ClaimSettleProvider".equals(request.getResourceType())) {
                payload = new String(
                        Files.readAllBytes(Paths
                                .get("src/main/java/nhcx/utility/crypto_utility/sample/Claim.txt")));
            } else if ("CoverageEligibilityRequest".equals(request.getResourceType())) {
                payload = new String(Files
                        .readAllBytes(Paths
                                .get("src/main/java/nhcx/utility/crypto_utility/sample/CoverageRequest.txt")));
            } else {
                System.out.println("Invalid file type specified.");

            }

            // Create headers
            Map<String, Object> headers = new HashMap<>();

            headers.put("alg", "RSA-OAEP-256");
            headers.put("enc", "A256GCM");
            headers.put("x-hcx-api_call_id", UUID.randomUUID());
            headers.put("x-hcx-workflow_id", "1");
            headers.put("x-hcx-request_id", UUID.randomUUID());
            headers.put("x-hcx-status", "request.initiated");
            headers.put("x-hcx-timestamp", timestamp);
            headers.put("x-hcx-sender_code", sender_code);
            headers.put("x-hcx-recipient_code", recipient_code);
            headers.put("x-hcx-correlation_id", coorelation_ID);

            PublicKey publicKey = session.fetchCertificates("1000003538");
            encryptedObject = keyProcessor.encryptRequest(publicKey, payload, headers);
            System.out.println("Encrypted Payload: " + encryptedObject);

        } catch (Exception e) {
            e.printStackTrace();
        }
        encryptResponse.setCorelationID(coorelation_ID.toString());
        encryptResponse.setEncyptedPayload(encryptedObject);

        return encryptResponse;
    }

}
