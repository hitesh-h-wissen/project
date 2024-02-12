package com.spring.security.auth_server.security.keys;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

public interface RSAKeyPairRepository {
    record RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    }

    List<RsaKeyPair> findKeyPairs();

    void delete(String id);

    void save(RsaKeyPair rsaKeyPair);
}
