package com.example.demologinwithauthentication.login.ulti;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 *
 * @author Dunglv@vmodev
 */
@Component
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig 
{
    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public Integer getRefreshExpirationDateInMs() {
        return refreshExpirationDateInMs;
    }

    public void setRefreshExpirationDateInMs(Integer refreshExpirationDateInMs) {
        this.refreshExpirationDateInMs = refreshExpirationDateInMs;
    }

    private Integer refreshExpirationDateInMs;

    public JwtConfig() {
    }
    
    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationAfterDays() {
        return tokenExpirationAfterDays;
    }

    public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
        this.tokenExpirationAfterDays = tokenExpirationAfterDays;
    }
    
    public String getAuthorizationHeader()
    {
        return HttpHeaders.AUTHORIZATION;
    }
}
