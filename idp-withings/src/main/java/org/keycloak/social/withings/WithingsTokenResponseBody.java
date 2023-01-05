package org.keycloak.social.withings;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class WithingsTokenResponseBody {
    @JsonProperty("userid")
    protected String userId;

    @JsonProperty("access_token")
    protected String accessToken;

    @JsonProperty("refresh_token")
    protected String refreshToken;

    @JsonProperty("expires_in")
    protected long expiresIn;

    @JsonProperty("scope")
    protected String scope;

    @JsonProperty("csrf_token")
    protected String csrfToken;

    @JsonProperty("token_type")
    protected String tokenType;

    protected Map<String, Object> otherClaims = new HashMap<>();

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getCsrfToken() {
        return csrfToken;
    }

    public void setCsrfToken(String csrfToken) {
        this.csrfToken = csrfToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @JsonAnyGetter
    public Map<String, Object> getOtherClaims() {
        return otherClaims;
    }

    @JsonAnySetter
    public void setOtherClaims(String name, Object value) {
        otherClaims.put(name, value);
    }

    @Override
    public String toString() {
        return "WithingsTokenResponseBody{" +
                "userId='" + userId + '\'' +
                ", accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", expiresIn=" + expiresIn +
                ", scope='" + scope + '\'' +
                ", csrfToken='" + csrfToken + '\'' +
                ", tokenType='" + tokenType + '\'' +
                ", otherClaims=" + otherClaims +
                '}';
    }
}
