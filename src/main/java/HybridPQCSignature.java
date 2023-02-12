import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class HybridPQCSignature {
    private final KeyPair rsaKeyPair;
    private final KeyPair dilithiumKeyPair;

    public HybridPQCSignature() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");
        keyPair.initialize(new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4));
        this.rsaKeyPair = keyPair.generateKeyPair();
        keyPair = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        keyPair.initialize(DilithiumParameterSpec.dilithium5);
        this.dilithiumKeyPair = keyPair.generateKeyPair();
    }

    public byte[][] signSeparately(byte[] message) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = Signature.getInstance("RSA", "BC");
        signature.initSign(rsaKeyPair.getPrivate());
        signature.update(message);
        byte[] rsaSignature = signature.sign();

        signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initSign(dilithiumKeyPair.getPrivate());
        signature.update(message);
        byte[] dilithiumSignature = signature.sign();

        return new byte[][]{rsaSignature, dilithiumSignature};
    }

    public boolean verifySeparately(byte[] message, byte[] rsaSignature, byte[] dilithiumSignature) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = Signature.getInstance("RSA", "BC");
        signature.initVerify(rsaKeyPair.getPublic());
        signature.update(message);
        boolean rsaVerification = signature.verify(rsaSignature);

        signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initVerify(dilithiumKeyPair.getPublic());
        signature.update(message);
        boolean dilithiumVerification = signature.verify(dilithiumSignature);

        return rsaVerification && dilithiumVerification;
    }

    public byte[][] signChained(byte[] message) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = Signature.getInstance("RSA", "BC");
        signature.initSign(rsaKeyPair.getPrivate());
        signature.update(message);
        byte[] rsaSignature = signature.sign();

        signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initSign(dilithiumKeyPair.getPrivate());
        signature.update(rsaSignature);
        byte[] dilithiumSignature = signature.sign();

        return new byte[][]{rsaSignature, dilithiumSignature};
    }

    public boolean verifyChained(byte[] message, byte[] rsaSignature, byte[] dilithiumSignature) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = Signature.getInstance("RSA", "BC");
        signature.initVerify(rsaKeyPair.getPublic());
        signature.update(message);
        boolean rsaVerification = signature.verify(rsaSignature);

        signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initVerify(dilithiumKeyPair.getPublic());
        signature.update(rsaSignature);
        boolean dilithiumVerification = signature.verify(dilithiumSignature);

        return rsaVerification && dilithiumVerification;
    }
}
