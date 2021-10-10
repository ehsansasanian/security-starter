package com.sasanian.securitystarter;

import com.sasanian.securitystarter.constants.SecurityConstants;
import com.sasanian.securitystarter.domain.CustomerUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.sasanian.securitystarter.constants.SecurityConstants.ClaimKeys.KEY_TYPE;

public final class SecurityUtils {
    public static Optional<String> getCurrentUserLogin() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(securityContext.getAuthentication())
                .map(authentication -> {
                    if (authentication.getPrincipal() instanceof UserDetails) {
                        UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
                        return springSecurityUser.getUsername();
                    } else if (authentication.getPrincipal() instanceof String) {
                        return (String) authentication.getPrincipal();
                    }
                    return null;
                });
    }

    public static Optional<CustomerUser> getCurrentCustomerUser() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(securityContext.getAuthentication())
                .map(Authentication::getPrincipal)
                .filter(o -> o instanceof CustomerUser)
                .map(o -> (CustomerUser) o);
    }

    public static Collection<String> getAuthorities() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return securityContext.getAuthentication()
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    public static Collection<String> getAuthorities(SecurityContext securityContext) {
        return securityContext.getAuthentication()
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    public static String getToken() {
        return "Bearer " + Jwts.builder()
                .setSubject("test")
                .claim(KEY_TYPE, SecurityConstants.Permissions.CUSTOMER)
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))
                .setExpiration(new Date())
                .signWith(SignatureAlgorithm.HS512, "secret")
                .compact();
    }

    public static Claims validate(String token) {
        try {
            final String jwt = token.replace("Bearer", "").trim();
            final Claims claims = Jwts.parser()
                    .setSigningKey("secret")
                    .parseClaimsJws(jwt)
                    .getBody();

            return claims.getExpiration().after(new Date()) ? claims : null;
        } catch (SignatureException e) {
            System.out.println("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            System.out.println("expired");
        } catch (UnsupportedJwtException e) {
            System.out.println("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            System.out.println("JWT token compact of handler are invalid.");
        }
        return null;
    }
}
