package com.example.KIREET.PGP_DEMO.PGP;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;

@org.springframework.stereotype.Service
public class PgpService {



    public ResponseEntity<?> encryptFile(MultipartFile file, MultipartFile publicKey, boolean asciiArmor) {
        // TODO: Implement encryption logic using Bouncy Castle

        try {
            Security.addProvider(new BouncyCastleProvider());



            // Read public key
            InputStream keyIn = new ByteArrayInputStream(publicKey.getBytes());
            PGPPublicKey pgpPublicKey = PgpUtil.readPublicKey(keyIn);


            // Compress the file content
            byte[] compressedData = PgpUtil.compressFile(file.getOriginalFilename(), file.getBytes());

            // Prepare output stream
            ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
            OutputStream out = asciiArmor ? new ArmoredOutputStream(encryptedOut) : encryptedOut;


            // Encrypt
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC")
            );
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));

            try (OutputStream cOut = encGen.open(out, compressedData.length)) {
                cOut.write(compressedData);
            }
            out.close();

            byte[] encryptedBytes = encryptedOut.toByteArray();
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"encrypted.pgp\"")
                    .body(encryptedBytes);


        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Encryption failed: " + e.getMessage());
        }



        //return ResponseEntity.ok("Encryption logic not yet implemented.");
    }

    public ResponseEntity<?> decryptFile(MultipartFile encryptedFile, MultipartFile privateKeyFile, String passphrase) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            InputStream encryptedData = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedFile.getBytes()));
            InputStream keyIn = new ByteArrayInputStream(privateKeyFile.getBytes());

            // Load private key
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            PGPObjectFactory pgpFactory = new PGPObjectFactory(encryptedData, new JcaKeyFingerprintCalculator());
            Object obj = pgpFactory.nextObject();

            PGPEncryptedDataList encList;
            if (obj instanceof PGPEncryptedDataList) {
                encList = (PGPEncryptedDataList) obj;
            } else {
                encList = (PGPEncryptedDataList) pgpFactory.nextObject();
            }

            PGPPublicKeyEncryptedData pbe = null;
            PGPPrivateKey privateKey = null;

            for (PGPEncryptedData ed : encList) {
                PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) ed;
                privateKey = PgpUtil.findPrivateKey(pgpSec, pked.getKeyID(), passphrase.toCharArray());
                if (privateKey != null) {
                    pbe = pked;
                    break;
                }
            }

            if (privateKey == null || pbe == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Private key not found or invalid passphrase.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider("BC").build(privateKey));

            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
            Object message = plainFact.nextObject();

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();

                int ch;
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }

                return ResponseEntity.ok()
                        .header("Content-Disposition", "attachment; filename=\"decrypted_" + ld.getFileName() + "\"")
                        .body(out.toByteArray());
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Unsupported encrypted data format.");
            }

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Decryption failed: " + e.getMessage());
        }
    }



}
