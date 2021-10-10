package com.sasanian.securitystarter.configs;

import com.sasanian.securitystarter.domain.CustomerUser;
import com.sasanian.securitystarter.domain.User;
import com.sasanian.securitystarter.jwt.TokenProvider;
import com.sasanian.securitystarter.mapper.CustomerTokenMapper;
import com.sasanian.securitystarter.mapper.UserTokenMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
@EnableConfigurationProperties(AppConfig.class)
public class AppAutoConfiguration {
    private final AppConfig appConfig;

    @Autowired
    public AppAutoConfiguration(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    @Bean
    public TokenProvider tokenProvider(AppConfig appConfig, Set<UserTokenMapper<? extends User>> userFactories) {
        return new TokenProvider(appConfig, userFactories);
    }

    @Bean
    public UserTokenMapper<CustomerUser> adminTokenMapper(AppConfig appConfig) {
        return new CustomerTokenMapper(appConfig);
    }

}