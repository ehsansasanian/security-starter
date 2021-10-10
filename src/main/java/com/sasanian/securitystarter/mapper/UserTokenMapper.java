package com.sasanian.securitystarter.mapper;

import com.sasanian.securitystarter.domain.User;
import io.jsonwebtoken.Claims;

import java.util.Date;

public interface UserTokenMapper<T extends User> {

    T userFromClaims(Claims claims);

    Date getExpirationDate();

    String getTypeStr();

    Class<T> getType();

    Claims generateClaims(User user);
}
