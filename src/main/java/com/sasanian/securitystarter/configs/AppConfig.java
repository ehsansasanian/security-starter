package com.sasanian.securitystarter.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public class AppConfig {
    private final AppConfig.Security security = new Security();

    public Security getSecurity() {
        return security;
    }

    public static class Security {
        private final AppConfig.Security.Authentication authentication = new Authentication();

        public Security() {
        }

        public AppConfig.Security.Authentication getAuthentication() {
            return this.authentication;
        }

        public static class Authentication {
            private final AppConfig.Security.Authentication.Jwt jwt = new Jwt();

            public Authentication() {
            }

            public AppConfig.Security.Authentication.Jwt getJwt() {
                return this.jwt;
            }

            public static class Jwt {
                private String secret;
                private int tokenValidityInSeconds;
                private String type;
                private String issuer;

                public Jwt() {
                    this.secret = "secret";
                    this.tokenValidityInSeconds = Integer.MAX_VALUE;
                    this.type = "Bearer";
                    this.issuer = "issuer";
                }

                public String getSecret() {
                    return secret;
                }

                public void setSecret(String secret) {
                    this.secret = secret;
                }

                public int getTokenValidityInSeconds() {
                    return tokenValidityInSeconds;
                }

                public void setTokenValidityInSeconds(int tokenValidityInSeconds) {
                    this.tokenValidityInSeconds = tokenValidityInSeconds;
                }

                public String getType() {
                    return type;
                }

                public void setType(String type) {
                    this.type = type;
                }

                public String getIssuer() {
                    return issuer;
                }

                public void setIssuer(String issuer) {
                    this.issuer = issuer;
                }
            }
        }
    }
}
