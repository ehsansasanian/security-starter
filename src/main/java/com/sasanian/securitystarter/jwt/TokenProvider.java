package com.sasanian.securitystarter.jwt;

import com.sasanian.securitystarter.configs.AppConfig;
import com.sasanian.securitystarter.constants.SecurityConstants;
import com.sasanian.securitystarter.domain.User;
import com.sasanian.securitystarter.mapper.UserTokenMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.sasanian.securitystarter.constants.SecurityConstants.ClaimKeys.KEY_ROLE;

public class TokenProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenProvider.class);
    private final String secretKey;
    private final String tokenType;
    private final Map<String, UserTokenMapper<? extends User>> userFactories = new HashMap<>();

    public TokenProvider(AppConfig appConfig, Set<UserTokenMapper<? extends User>> userFactories) {
        this.secretKey = appConfig.getSecurity().getAuthentication().getJwt().getSecret();
        this.tokenType = appConfig.getSecurity().getAuthentication().getJwt().getType();
        userFactories.forEach(u -> this.userFactories.put(u.getTypeStr(), u));
    }

    private Claims validateToken(String authToken) {
        try {
            final String jwt = authToken.replace(tokenType, "").trim();
            return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (SignatureException e) {
            LOGGER.info("Invalid JWT signature.");
            LOGGER.trace("Invalid JWT signature trace {}", e.toString());
        } catch (MalformedJwtException e) {
            LOGGER.info("Invalid JWT token.");
            LOGGER.trace("Invalid JWT token trace: {}", e.toString());
        } catch (ExpiredJwtException e) {
            LOGGER.info("Expired JWT token.");
            LOGGER.trace("Expired JWT token trace: {}", e.toString());
        } catch (UnsupportedJwtException e) {
            LOGGER.info("Unsupported JWT token.");
            LOGGER.trace("Unsupported JWT token trace: {}", e.toString());
        } catch (IllegalArgumentException e) {
            LOGGER.info("JWT token compact of handler are invalid.");
            LOGGER.trace("JWT token compact of handler are invalid trace: {}", e.toString());
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = this.validateToken(token);

        if (Objects.isNull(claims)) {
            return null;
        }

        String type = (String) claims.get(tokenType);
        UserTokenMapper<? extends User> userTokenMapper = userFactories.get(type);
        User principal = userTokenMapper.userFromClaims(claims);

        return new UsernamePasswordAuthenticationToken(principal, token, principal.getAuthorities());
    }

    public String createToken(Authentication auth) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Creating Token For The User = {}", auth.getName());
        }
        String authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        UserTokenMapper<? extends User> userTokenMapper = userFactories.values()
                .stream().filter(uf -> uf.getType().isInstance(auth.getPrincipal()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(""));

        Claims claims = userTokenMapper.generateClaims((User) auth.getPrincipal());
        claims.put(KEY_ROLE, authorities);

        return Jwts.builder()
                .setSubject(auth.getName())
                .setClaims(claims)
                .setIssuer(null)
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))
                .setExpiration(userTokenMapper.getExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }
}
