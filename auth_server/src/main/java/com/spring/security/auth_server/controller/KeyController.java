package com.spring.security.auth_server.controller;

import com.spring.security.auth_server.security.keys.Keys;
import com.spring.security.auth_server.security.keys.RSAKeyPairRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

import static com.spring.security.auth_server.security.keys.RSAKeyPairRepository.RsaKeyPair;


@RestController
public class KeyController {

    private final RSAKeyPairRepository repository;
    private final Keys keys;

    public KeyController(RSAKeyPairRepository repository, Keys keys) {
        this.repository = repository;
        this.keys = keys;
    }

    @GetMapping("/oauth2/new_jwks")
    public String generate() {
        RsaKeyPair keypair = keys.generateKeyPair(Instant.now());
        this.repository.save(keypair);
        return keypair.id();
    }

}