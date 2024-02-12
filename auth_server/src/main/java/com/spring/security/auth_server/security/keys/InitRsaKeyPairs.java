package com.spring.security.auth_server.security.keys;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.Instant;

import static com.spring.security.auth_server.security.keys.RSAKeyPairRepository.RsaKeyPair;

@Component
public class InitRsaKeyPairs implements ApplicationRunner {

    private final RSAKeyPairRepository rsaKeyPairRepository;
    private final Keys keys;

    public InitRsaKeyPairs(RSAKeyPairRepository rsaKeyPairRepository, Keys keys) {
        this.rsaKeyPairRepository = rsaKeyPairRepository;
        this.keys = keys;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (rsaKeyPairRepository.findKeyPairs().isEmpty()) {
            RsaKeyPair rsaKeyPair = keys.generateKeyPair(Instant.now());
            this.rsaKeyPairRepository.save(rsaKeyPair);
        }
    }
}
