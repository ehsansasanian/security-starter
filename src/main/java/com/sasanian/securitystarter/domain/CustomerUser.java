package com.sasanian.securitystarter.domain;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sasanian.securitystarter.constants.SecurityConstants.ClaimKeys.KEY_ROLE;

public class CustomerUser extends User {

    public CustomerUser(Claims claims) {
        super(claims.getSubject(), null, getAuthorities(claims));
    }

    public CustomerUser(String username, String password, List<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    private static List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        if (claims.get(KEY_ROLE) instanceof List) {
            List<String> authorities = (List) claims.get(KEY_ROLE);
            return authorities.stream()
                    .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        } else {
            return Stream.of(((String) claims.get(KEY_ROLE)).split(","))
                    .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        }
    }

}
