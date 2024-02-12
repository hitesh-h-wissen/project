package com.spring.security.auth_server.security.keys;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

@Component
public class JdbcRsaKeyPairRepository implements RSAKeyPairRepository {
    private final JdbcTemplate jdbcTemplate;
    private final RowMapper<RsaKeyPair> keyPairRowMapper;
    private final RsaPublicKeyConverter rsaPublicKeyConverter;
    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;

    public JdbcRsaKeyPairRepository(
            JdbcTemplate jdbcTemplate,
            RowMapper<RsaKeyPair> keyPairRowMapper,
            RsaPublicKeyConverter rsaPublicKeyConverter,
            RsaPrivateKeyConverter rsaPrivateKeyConverter) {
        this.jdbcTemplate = jdbcTemplate;
        this.keyPairRowMapper = keyPairRowMapper;
        this.rsaPublicKeyConverter = rsaPublicKeyConverter;
        this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
    }

    @Override
    public List<RsaKeyPair> findKeyPairs() {
        String sql = "select * from rsa_key_pairs order by created desc";
        return jdbcTemplate.query(sql, this.keyPairRowMapper);
    }

    @Override
    public void delete(String id) {
        String sql = "delete from rsa_key_pairs where id = ?";
        jdbcTemplate.update(sql);

    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        String sql = "insert into rsa_key_pairs (id, created, public_key, private_key) values (?,?,?,?)";
        try (ByteArrayOutputStream privateStream = new ByteArrayOutputStream(); ByteArrayOutputStream publicStream = new ByteArrayOutputStream()) {
            this.rsaPrivateKeyConverter.serialize(rsaKeyPair.privateKey(), privateStream);
            this.rsaPublicKeyConverter.serialize(rsaKeyPair.publicKey(), publicStream);
            this.jdbcTemplate.update(sql,
                    rsaKeyPair.id(),
                    new Date(rsaKeyPair.created().toEpochMilli()),
                    publicStream.toString(),
                    privateStream.toString());

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
