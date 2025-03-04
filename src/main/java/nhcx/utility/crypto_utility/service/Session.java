package nhcx.utility.crypto_utility.service;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component

public class Session {
    private final WebClient webClient;

    public Session(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @Value("${client.id}")
    private String clientId;
    @Value("${client.secret}")
    private String clientSecret;

    @SuppressWarnings("null")
    public PublicKey fetchCertificates(String participantId) {
        String url = "https://apisbx.abdm.gov.in/pmjay/sbxhcx/participanthcxservice/fetch/certs";
        String responseString = "";
        X509Certificate certificate = null;

        try {

            String urlTOken = "https://dev.abdm.gov.in/gateway/v0.5/sessions";
            String sessionToken = "";
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("clientId", clientId);
            requestBody.put("clientSecret", clientSecret);
            sessionToken = webClient.post()
                    .uri(urlTOken)
                    .header("Content-Type", "application/json")
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
            String fetchRequestBody = "{\"participantid\": \"" + participantId + "\"}";
            responseString = webClient.post()
                    .uri(url)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("bearer_auth", sessionToken)
                    .bodyValue(fetchRequestBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(responseString);
            String encryptionCert = jsonNode.get("encryption_cert").asText();

            String base64Cert = encryptionCert
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            // Decode Base64 string
            byte[] certBytes = Base64.getDecoder().decode(base64Cert);

            // Create a CertificateFactory
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // Generate an X509Certificate from the bytes
            certificate = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(certBytes));

        } catch (Exception e) {
            e.printStackTrace();
        }

        // Extract and return the public key
        return certificate.getPublicKey();

        // return responseString;
    }

}
