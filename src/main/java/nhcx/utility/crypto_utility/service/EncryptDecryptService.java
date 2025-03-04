package nhcx.utility.crypto_utility.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import nhcx.utility.crypto_utility.model.DecryptResponse;
import nhcx.utility.crypto_utility.model.EncryptRequest;
import nhcx.utility.crypto_utility.model.EncryptResponse;

@Service
public class EncryptDecryptService {

    @Autowired
    ProcessRequest processRequest;

    public DecryptResponse decryptMessage(String encryptedText) {
        processRequest.decryptRequest(encryptedText);
        return processRequest.decryptRequest(encryptedText);
    }

    public EncryptResponse encryptMessage(EncryptRequest request) {

        return processRequest.encryptRequest(request);

    }
}
