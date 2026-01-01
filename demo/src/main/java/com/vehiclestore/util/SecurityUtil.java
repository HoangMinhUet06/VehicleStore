package com.vehiclestore.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.util.Base64;

@Service
public class SecurityUtil {

    private final JwtEncoder jwtEncoder;

    // Use HS256 algorithm - requires at least 32 bytes (256 bits) secret key
    // HS384 needs 48 bytes, HS512 needs 64 bytes
    public static final MacAlgorithm JWT_ALGORITHM = MacAlgorithm.HS256;

    public SecurityUtil(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @Value("${vehcilestore.jwt.base64-secret}")
    private String jwtKey;

    @Value("${vehcilestore.jwt.token-validity-in-seconds}")
    private long jwtExpiration;

    // Create JWT token from authenticated user
    // Parameter: authentication - the authenticated user info from Spring Security
    // Returns: JWT token string
    public String createToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant validity = now.plus(this.jwtExpiration, ChronoUnit.SECONDS);

        // Build JWT claims (payload)
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(validity)
                .subject(authentication.getName())
                .claim("RyanLee", authentication.getName())
                .build();

        // Build JWT header with algorithm
        JwsHeader header = JwsHeader.with(JWT_ALGORITHM).build();

        // Encode and return token
        return this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
