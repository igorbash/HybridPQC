import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

public class HybridPQCKEM {

    public byte[][] getKeys() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] ecdhKey = getECDHKey();
        byte[] kyberKey = getKyberKey();

        return new byte[][]{ecdhKey, kyberKey};
    }

    private byte[] getECDHKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("B-571"));
        PublicKey recipientPublic = keyPairGenerator.generateKeyPair().getPublic();
        keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("B-571"));
        PrivateKey initiatorPrivate = keyPairGenerator.generateKeyPair().getPrivate();
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDH", "BC");
        agreement.init(initiatorPrivate);
        agreement.doPhase(recipientPublic, true);
        SecretKey agreedKey = agreement.generateSecret("AES[256]");
        return agreedKey.getEncoded();
    }

    private byte[] getKyberKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        keyPairGenerator.initialize(KyberParameterSpec.kyber1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Kyber", "BCPQC");
        keyGenerator.init(new KEMGenerateSpec(keyPair.getPublic(), "AES"));
        SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        return secretKeyWithEncapsulation.getEncoded();
    }
}
