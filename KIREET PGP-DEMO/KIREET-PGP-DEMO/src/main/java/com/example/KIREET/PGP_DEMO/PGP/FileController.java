package com.example.KIREET.PGP_DEMO.PGP;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/pgp")
public class FileController {

    @Autowired
    public PgpService pgpService;

    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptFile(@RequestParam("file") MultipartFile file,
                                         @RequestParam("publicKey") MultipartFile publicKey,
                                         @RequestParam(value = "asciiArmor", defaultValue = "true") boolean asciiArmor) {
        return pgpService.encryptFile(file, publicKey, asciiArmor);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decryptFile(@RequestParam("file") MultipartFile file,
                                         @RequestParam("privateKey") MultipartFile privateKey,
                                         @RequestParam("passphrase") String passphrase) {
        return pgpService.decryptFile(file, privateKey, passphrase);
    }

}
