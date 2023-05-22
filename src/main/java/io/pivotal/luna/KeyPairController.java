package io.pivotal.luna;

import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static io.pivotal.luna.Util.zip;

@RestController
final class KeyPairController {

    private final KeyPair keyPair;

    KeyPairController(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @GetMapping("/key-pair")
    Map<String, String> keyPair() {

        String privateKey = Base64.getEncoder().encodeToString(this.keyPair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());

        return zip(
                new String[] {
                        "private",
                        "public"
                },
                new String[] {
                        privateKey,
                        publicKey
                });

    }

}
