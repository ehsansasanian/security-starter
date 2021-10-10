package com.sasanian.securitystarter.mapper;

import com.sasanian.securitystarter.configs.AppConfig;
import com.sasanian.securitystarter.domain.CustomerUser;
import com.sasanian.securitystarter.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Date;

import static com.sasanian.securitystarter.constants.SecurityConstants.ClaimKeys.KEY_TYPE;

public class CustomerTokenMapper implements UserTokenMapper<CustomerUser> {
    private final AppConfig appConfig;

    public CustomerTokenMapper(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    @Override
    public CustomerUser userFromClaims(Claims claims) {
        return new CustomerUser(claims);
    }

    @Override
    public Claims generateClaims(User user) {
        CustomerUser humanUser = (CustomerUser) user;
        Claims claims = Jwts.claims();
        claims.put(KEY_TYPE, getTypeStr());
        claims.setSubject(humanUser.getUsername());
        claims.setIssuer(appConfig.getSecurity().getAuthentication().getJwt().getIssuer());
        claims.setIssuedAt(Timestamp.valueOf(LocalDateTime.now()));
        return claims;
    }

    @Override
    public Date getExpirationDate() {
        return new Date(
                System.currentTimeMillis() + (appConfig.getSecurity()
                        .getAuthentication().getJwt().getTokenValidityInSeconds()));
    }

    @Override
    public String getTypeStr() {
        return "human";
    }

    @Override
    public Class<CustomerUser> getType() {
        return CustomerUser.class;
    }
}
