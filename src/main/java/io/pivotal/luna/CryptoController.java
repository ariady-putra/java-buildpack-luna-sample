package io.pivotal.luna;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.safenetinc.luna.LunaUtils;

import static io.pivotal.luna.Util.*;

@RestController
final class CryptoController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Cipher decryptionCipher;

    private final Cipher encryptionCipher;

    private final Signature signingSignature;

    private final Signature verificationSignature;

    CryptoController(
            @Qualifier("decryptionCipher") Cipher decryptionCipher,
            @Qualifier("encryptionCipher") Cipher encryptionCipher,
            @Qualifier("signingSignature") Signature signingSignature,
            @Qualifier("verificationSignature") Signature verificationSignature) {

        this.decryptionCipher = decryptionCipher;
        this.encryptionCipher = encryptionCipher;
        this.signingSignature = signingSignature;
        this.verificationSignature = verificationSignature;

    }

    @PostMapping(value = "/decrypt", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, String> decrypt(@RequestBody Map<String, String> payload) throws GeneralSecurityException {

        String cipherText = Optional
                .of(payload.get("cipher-text"))
                .orElseThrow(() -> new IllegalArgumentException("Payload must contain 'cipher-text'"));
        this.logger.info("Decrypting Cipher Text '{}'", cipherText);

        this.decryptionCipher.update(LunaUtils.hexStringToByteArray(cipherText));
        String message = new String(this.decryptionCipher.doFinal(), Charset.defaultCharset()).trim();

        return zip(
                new String[] {
                        "cipher-text",
                        "message"
                },
                new String[] {
                        cipherText,
                        message
                });

    }

    @PostMapping(value = "/encrypt", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, String> encrypt(@RequestBody Map<String, String> payload) throws GeneralSecurityException {

        String message = Optional
                .of(payload.get("message"))
                .orElseThrow(() -> new IllegalArgumentException("Payload must contain 'message'"));
        this.logger.info("Encrypting Message '{}'", message);

        this.encryptionCipher.update(message.getBytes(Charset.defaultCharset()));
        String cipherText = LunaUtils.getHexString(this.encryptionCipher.doFinal(), false);

        return zip(
                new String[] {
                        "message",
                        "cipher-text"
                },
                new String[] {
                        message,
                        cipherText
                });

    }

    @PostMapping(value = "/sign", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, String> sign(@RequestBody Map<String, String> payload) throws Exception {

        String message = Optional
                .of(payload.get("message"))
                .orElseThrow(() -> new IllegalArgumentException("Payload must contain 'message'"));
        this.logger.info("Signing Message '{}'", message);

        this.signingSignature.update(message.getBytes(Charset.defaultCharset()));
        String signature = LunaUtils.getHexString(this.signingSignature.sign(), false);

        return zip(
                new String[] {
                        "message",
                        "signature"
                },
                new String[] {
                        message,
                        signature
                });

    }

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> verify(@RequestBody Map<String, String> payload) throws GeneralSecurityException {

        String message = Optional
                .of(payload.get("message"))
                .orElseThrow(() -> new IllegalArgumentException("Payload must contain 'message'"));
        String signature = Optional
                .of(payload.get("signature"))
                .orElseThrow(() -> new IllegalArgumentException("Payload must contain 'signature'"));
        this.logger.info("Verifying Message '{}' and Signature '{}'", message, signature);

        this.verificationSignature.update(message.getBytes(Charset.defaultCharset()));
        boolean verified = this.verificationSignature.verify(LunaUtils.hexStringToByteArray(signature));

        return zip(
                new String[] {
                        "message",
                        "signature",
                        "verified"
                },
                new Object[] {
                        message,
                        signature,
                        verified
                });

    }

}
