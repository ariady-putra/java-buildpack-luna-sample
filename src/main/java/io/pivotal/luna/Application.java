package io.pivotal.luna;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.key.LunaPrivateKeyRsa;
import com.safenetinc.luna.provider.key.LunaPublicKeyRsa;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;

import javax.crypto.Cipher;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;

@SpringBootApplication
public class Application {

    @Value("${luna_hsm.security_provider}")
    private String securityProvider = "LunaProvider";

    @Value("${luna_hsm.signature_algorithm}")
    private String signatureAlgorithm = "RSA";

    @Value("${lunahsm.cipher_transformation}")
    private String cipherTransformation = "RSA/NONE/NoPadding";

    @Value("${luna_hsm.token_label}")
    private String tokenLabel;

    @Value("${luna_hsm.login_password}")
    private String loginPassword;

    @Value("${luna_hsm.key_alias.private}")
    private String privateKeyAlias;

    @Value("${luna_hsm.key_alias.public}")
    private String publicKeyAlias;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    Cipher decryptionCipher(KeyPair keyPair) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(cipherTransformation, securityProvider);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        return cipher;

    }

    @Bean
    Cipher encryptionCipher(KeyPair keyPair) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(cipherTransformation, securityProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        return cipher;

    }

    @Bean
    @DependsOn("slotManager")
    KeyPair keyPair() throws Exception {

        int slot = slotManager().findSlotFromLabel(tokenLabel);

        LunaTokenObject privateKey = LunaTokenObject.LocateKeyByAlias(privateKeyAlias, slot);
        LunaPrivateKeyRsa privateKeyRSA = new LunaPrivateKeyRsa(privateKey);

        LunaTokenObject publicKey = LunaTokenObject.LocateKeyByAlias(publicKeyAlias, slot);
        LunaPublicKeyRsa publicKeyRSA = new LunaPublicKeyRsa(publicKey);

        return new KeyPair(publicKeyRSA, privateKeyRSA);

    }

    @Bean
    Signature signingSignature(KeyPair keyPair) throws GeneralSecurityException {

        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(keyPair.getPrivate());

        return signature;

    }

    @Bean(destroyMethod = "logout")
    LunaSlotManager slotManager() {

        LunaSlotManager slotManager = LunaSlotManager.getInstance();
        slotManager.login(loginPassword);

        return slotManager;

    }

    @Bean
    Signature verificationSignature(KeyPair keyPair) throws GeneralSecurityException {

        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(keyPair.getPublic());

        return signature;

    }

}
