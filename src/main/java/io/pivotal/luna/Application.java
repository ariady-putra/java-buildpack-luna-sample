package io.pivotal.luna;

import com.safenetinc.luna.LunaAPI;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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

    @Value("${lunahsm.key_size}")
    private int keySize = 1024;

    @Value("${lunahsm.private_key}")
    private String privateKey;

    @Value("${lunahsm.public_key}")
    private String publicKey;

    @Value("${lunahsm.login.token_label}")
    private String tokenLabel;

    @Value("${lunahsm.login.password}")
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

        LunaProvider luna = LunaProvider.getInstance();
        System.out.println("\nLuna Provider:\n");
        System.out.println("Info: " + luna.getInfo());
        System.out.println("Name: " + luna.getName());
        System.out.println("Version: " + luna.getVersion());

        LunaAPI api = slotManager().getLunaAPI();
        System.out.println("\nLuna API:\n");
        for (int slot : api.GetSlotList()) {
            // System.out.println("Slot: " + slot);

            String label = api.GetTokenLabel(slot);
            // System.out.println("if(" + label + ".equalsIgnoreCase(" + tokenLabel + "))");
            if (label.trim().equalsIgnoreCase(tokenLabel)) {
                int session = api.OpenSession(slot);
                // System.out.println("Session handle: " + session);

                System.out.println("Label: " + label);
                System.out.println("Serial Number: " + api.GetTokenSerialNumber(slot));

                StringBuilder version = new StringBuilder();
                Arrays.stream(api.GetTokenFirmwareVersion(slot))
                        .forEachOrdered(v -> version.append(v + "."));
                version.deleteCharAt(version.length() - 1);
                System.out.println("Firmware Version: " + version);

                System.out.println("Key list:\n");
                for (int key : api.GetKeyList(session)) {
                    System.out.println("\tKey: " + key);
                    System.out.println("\tAlias: " + api.GetKeyAlias(session, key));

                    System.out.println("\tAttributes:\n");
                    for (long attribute : api.GetInitialAttributes(session, key)) {
                        System.out.println("\t\tAttribute: " + attribute);
                        System.out.println("\t\t" + api.GetLargeAttribute(session, key, attribute));
                        System.out.println();
                    }

                    System.out.println();
                }

                api.CloseSession(slot);
                // System.out.println();
                break;
            }
        }

        // KeyPairGenerator keyPairGenerator = KeyPairGenerator
        // .getInstance(
        // algorithm,
        // provider);
        // keyPairGenerator.initialize(keySize);

        // return keyPairGenerator.generateKeyPair();

        KeyFactory rsa = KeyFactory.getInstance("RSA", provider);

        // Private Key
        byte[] b64private = Base64.getDecoder().decode(privateKey
                .replace("\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .trim());
        ASN1EncodableVector v1 = new ASN1EncodableVector();
        v1.add(new ASN1Integer(0));
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()));
        v2.add(DERNull.INSTANCE);
        v1.add(new DERSequence(v2));
        v1.add(new DEROctetString(b64private));
        ASN1Sequence seq = new DERSequence(v1);
        byte[] der = seq.getEncoded("DER");
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(der);

        // Public Key
        byte[] b64public = Base64.getDecoder().decode(publicKey
                .replace("\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim());
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(b64public);

        return new KeyPair(
                rsa.generatePublic(x509),
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
        slotManager.login(tokenLabel, password);

        return slotManager;

    }

    @Bean
    Signature verificationSignature(KeyPair keyPair) throws GeneralSecurityException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(keyPair.getPublic());

        return signature;

    }

}
