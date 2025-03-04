package nhcx.utility.crypto_utility.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import nhcx.utility.crypto_utility.model.DecryptRequest;
import nhcx.utility.crypto_utility.model.DecryptResponse;
import nhcx.utility.crypto_utility.model.EncryptRequest;
import nhcx.utility.crypto_utility.model.EncryptResponse;
import nhcx.utility.crypto_utility.service.EncryptDecryptService;

@RestController
@RequestMapping("/api")
public class Controller {

    @Autowired
    private EncryptDecryptService encryptDecryptService;

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) {
        return encryptDecryptService.decryptMessage(request.getEncryptedText());
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody EncryptRequest request) {
        return encryptDecryptService.encryptMessage(request);
    }
}
