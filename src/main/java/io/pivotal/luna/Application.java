package io.pivotal.luna;

import com.safenetinc.luna.LunaSlotManager;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;

@SpringBootApplication
public class Application {

    @Value("${lunahsm.provider}")
    private String provider = "LunaProvider";

    @Value("${lunahsm.algorithm}")
    private String algorithm = "RSA";

    @Value("${lunahsm.transformation}")
    private String transformation = "RSA/NONE/NoPadding";

    // @Value("${lunahsm.key_size}")
    // private int keySize = 1024;

    @Value("${lunahsm.private_key}")
    private String key;

    @Value("${lunahsm.password}")
    private String password;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    Cipher decryptionCipher(KeyPair keyPair) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation, provider);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        return cipher;

    }

    @Bean
    Cipher encryptionCipher(KeyPair keyPair) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation, provider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        return cipher;

    }

    @Bean
    @DependsOn("slotManager")
    KeyPair keyPair() throws Exception {

        // KeyPairGenerator keyPairGenerator = KeyPairGenerator
        // .getInstance(
        // algorithm,
        // provider);
        // keyPairGenerator.initialize(keySize);

        // return keyPairGenerator.generateKeyPair();

        byte[] b64 = Base64.getDecoder().decode(key
                .replace("\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .trim());
        ASN1EncodableVector v1 = new ASN1EncodableVector();
        v1.add(new ASN1Integer(0));
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()));
        v2.add(DERNull.INSTANCE);
        v1.add(new DERSequence(v2));
        v1.add(new DEROctetString(b64));

        ASN1Sequence seq = new DERSequence(v1);
        byte[] der = seq.getEncoded("DER");

        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(der);
        KeyFactory rsa = KeyFactory.getInstance("RSA", provider);

        return new KeyPair(
                rsa.generatePublic(pkcs8),
                rsa.generatePrivate(pkcs8));

    }

    @Bean
    Signature signingSignature(KeyPair keyPair) throws GeneralSecurityException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(keyPair.getPrivate());

        return signature;

    }

    @Bean(destroyMethod = "logout")
    LunaSlotManager slotManager() {

        LunaSlotManager slotManager = LunaSlotManager.getInstance();
        slotManager.login(password);

        return slotManager;

    }

    @Bean
    Signature verificationSignature(KeyPair keyPair) throws GeneralSecurityException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(keyPair.getPublic());

        return signature;

    }

}
