import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.*;

public class Main {
    static final byte[] MESSAGE = "MESSAGE".getBytes();

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        HybridPQCSignature hybridPQC = new HybridPQCSignature();

        long start = System.nanoTime();
        byte[][] signatures = hybridPQC.signSeparately(MESSAGE);
        long end = System.nanoTime();
        System.out.println("Separate Sign: " + (end - start) / 1_000_000_000.00 + " seconds");
        start = System.nanoTime();
        assert hybridPQC.verifySeparately(MESSAGE, signatures[0], signatures[1]);
        end = System.nanoTime();
        System.out.println("Separate verification: " + (end - start) / 1_000_000_000.00 + " seconds");

        start = System.nanoTime();
        signatures = hybridPQC.signChained(MESSAGE);
        end = System.nanoTime();
        System.out.println("Chained Sign: " + (end - start) / 1_000_000_000.00 + " seconds");
        start = System.nanoTime();
        assert hybridPQC.verifyChained(MESSAGE, signatures[0], signatures[1]);
        end = System.nanoTime();
        System.out.println("Chained verification: " + (end - start) / 1_000_000_000.00 + " seconds");

        new HybridPQCKEM().getKeys();
    }
}
