package com.example.KIREET.PGP_DEMO.PGP;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;
import java.util.Date;

public class PgpUtil {


    public static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        for (PGPPublicKeyRing keyRing : keyRingCollection) {
            for (PGPPublicKey key : keyRing) {
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }


    public static byte[] compressFile(String fileName, byte[] data) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        try (OutputStream cos = comData.open(bOut)) {
            PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
            try (OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, fileName, data.length, new Date())) {
                pOut.write(data);
            }
        }
        return bOut.toByteArray();
    }



    public static PGPPrivateKey findPrivateKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] passphrase)
            throws PGPException {
        PGPSecretKey secretKey = pgpSec.getSecretKey(keyID);
        if (secretKey == null) {
            return null;
        }
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC").build(passphrase);
        return secretKey.extractPrivateKey(decryptor);
    }


}
