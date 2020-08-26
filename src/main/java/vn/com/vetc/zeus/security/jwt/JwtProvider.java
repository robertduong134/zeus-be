package vn.com.vetc.zeus.security.jwt;

import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;
import vn.com.vetc.zeus.security.services.UserPrinciple;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${zeus.app.jwt-secret}")
    private String jwtSecret;

    @Value("${zeus.app.jwt-expiration}")
    private int jwtExpiration;

    @Value("${zeus.app.jwt-refresh-expiration}")
    private int jwtRefreshExpiration;

    private Clock clock = DefaultClock.INSTANCE;

    public String generateJwtToken(Authentication authentication) {
        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpiration * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    public Boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }

        return false;
    }

    public String getStringKey(String keyName){
        String data = "";
        ClassPathResource cpr = new ClassPathResource(keyName);
        try {
            byte[] bdata = FileCopyUtils.copyToByteArray(cpr.getInputStream());
            data = new String(bdata, StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.warn("IOException", e);
        }
        return data;
    }

    public String generateAccessTokenRSA(String username) {
        Signer signer = null;
        try {
            signer = RSASigner.newSHA256Signer(getStringKey("private_key.pem"));
        } catch (Exception e) {
            e.printStackTrace();
        }

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

        JWT jwt = new JWT()
                .setIssuedAt(now)
                .setSubject(username)
                .setExpiration(now.plusSeconds(jwtExpiration));
        String encodedJWT = JWT.getEncoder().encode(jwt, signer);
        return encodedJWT;
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtRefreshExpiration * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public Boolean validateTokenRSA(String authToken) {
        try {
            // Build an RSA verifier using an RSA Public Key
            Verifier verifier = RSAVerifier.newVerifier(getStringKey("public_key.pem"));
            // Verify and decode the encoded string JWT to a rich object
            JWT jwt = JWT.getDecoder().decode(authToken, verifier);
            return true;
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return false;
    }

    public String getUserNameFromTokenRSA(String token) {
        return getAllClaims(token).get("sub").toString();
    }

    public String getUserIdFromTokenRSA(String token) {
        return getAllClaims(getJwtRaw(token)).get("userId").toString();
    }

    public String getShopCodeFromTokenRSA(String token) {
        return getAllClaims(token).get("shopCode").toString();
    }

    public Date getIssuedAtDateFromTokenRSA(String token) {
        return (Date) getAllClaims(token).get("iat");
    }

    public Date getExpirationDateFromTokenRSA(String token) {
        return (Date) getAllClaims(token).get("exp");
    }

    public Map<String, Object> getAllClaims(String token){
        // Build an EC verifier using an EC Public Key
        Verifier verifier = RSAVerifier.newVerifier(getStringKey("public_key.pem"));

        // Verify and decode the encoded string JWT to a rich object
        JWT jwt = JWT.getDecoder().decode(token, verifier);

        return jwt.getAllClaims();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromTokenRSA(token);
        return expiration.before(clock.now());
    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        if(lastPasswordReset == null)
            return false;

        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getIssuedAtDateFromTokenRSA(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public int getJwtExpiration() {
        return jwtExpiration;
    }

    public int getJwtRefreshExpiration(){
        return jwtRefreshExpiration;
    }

    public String getJwtRaw(String authorizationHeader){
        return authorizationHeader.replaceAll("Bearer", "").trim();
    }
}