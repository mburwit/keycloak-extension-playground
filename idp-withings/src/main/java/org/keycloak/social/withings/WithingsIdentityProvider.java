package org.keycloak.social.withings;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.keycloak.broker.oidc.OIDCIdentityProvider.ACCESS_TOKEN_EXPIRATION;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE;

public class WithingsIdentityProvider extends AbstractOAuth2IdentityProvider<WithingsIdentityProviderConfig>
        implements SocialIdentityProvider<WithingsIdentityProviderConfig> {

    public static final String OAUTH2_PARAMETER_ACTION = "action";
    public static final String OAUTH2_PARAMETER_BODY = "body";
    public static final String OAUTH2_PARAMETER_EXPIRES_IN = "expires_in";

    public static final String AUTH_URL = "https://account.withings.com/oauth2_user/authorize2";
    public static final String TOKEN_URL = "https://wbsapi.withings.net/v2/oauth2";
    public static final String DEFAULT_SCOPE = "user.info";
    public static final String ACTION_REQUEST_TOKEN = "requesttoken";

    public WithingsIdentityProvider(KeycloakSession session, WithingsIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new WithingsEndpoint(callback, realm, event);
    }

    protected SimpleHttp getRefreshTokenRequest(KeycloakSession session, String refreshToken) {
        SimpleHttp refreshTokenRequest = SimpleHttp.doPost(getConfig().getTokenUrl(), session)
                .param(OAUTH2_PARAMETER_ACTION, ACTION_REQUEST_TOKEN)
                .param(OAUTH2_GRANT_TYPE_REFRESH_TOKEN, refreshToken)
                .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_REFRESH_TOKEN);
        return authenticateTokenRequest(refreshTokenRequest);
    }

    protected class WithingsEndpoint extends Endpoint {
        public WithingsEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode) {
            SimpleHttp request = super.generateTokenRequest(authorizationCode);

            request.param(OAUTH2_PARAMETER_ACTION, ACTION_REQUEST_TOKEN);

            return request;
        }
    }

    public BrokeredIdentityContext getFederatedIdentity(String response) {
        String body = extractTokenFromResponse(response, getBodyResponseParameter());
        WithingsTokenResponseBody tokenResponse;
        try {
            tokenResponse = JsonSerialization.readValue(body, WithingsTokenResponseBody.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode token response.", e);
        }
        verifyAccessToken(tokenResponse);
        try {
            BrokeredIdentityContext identity = extractIdentity(tokenResponse);
            if (getConfig().isStoreToken()) {
                if (tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                identity.setToken(response);
            }
            return identity;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from token response.", e);
        }
    }

    private void verifyAccessToken(WithingsTokenResponseBody tokenResponse) {
        String accessToken = tokenResponse.getAccessToken();

        if (accessToken == null) {
            throw new IdentityBrokerException("No access_token from server. response='" + tokenResponse);
        }
    }

    private BrokeredIdentityContext extractIdentity(WithingsTokenResponseBody tokenResponse) {
        if (tokenResponse == null) {
            throw new IdentityBrokerException("Cannot extract identity from token response: null");
        }
        BrokeredIdentityContext identity = new BrokeredIdentityContext(tokenResponse.getUserId());
        identity.setBrokerUserId(getConfig().getAlias() + "." + tokenResponse.getUserId());
        identity.setUsername(tokenResponse.getUserId());
        identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);

        return identity;
    }

    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        logger.debug("[WithingsIdentityProvider::exchangeStoredToken()]");
        FederatedIdentityModel model = session.users().getFederatedIdentity(authorizedClient.getRealm(), tokenSubject, getConfig().getAlias());
        if (model == null || model.getToken() == null) {
            logger.debug("[WithingsIdentityProvider::exchangeStoredToken()]: model == null || model.getToken() == null ");
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try {
            String modelTokenString = model.getToken();
            logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()] - token: {0}", modelTokenString);
            WithingsTokenResponseBody tokenResponse = JsonSerialization.readValue(modelTokenString, WithingsTokenResponseBody.class);
            Integer exp = (Integer) tokenResponse.getOtherClaims().get(ACCESS_TOKEN_EXPIRATION);
            int currentTime = Time.currentTime();
            if (exp != null && exp < currentTime) {
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: exp != null && exp[{0}] < Time.currentTime()[{1}] => access token expired!", exp, currentTime);
                if (tokenResponse.getRefreshToken() == null) {
                    logger.debug("[WithingsIdentityProvider::exchangeStoredToken()] - have no refresh token");
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                String response = getRefreshTokenRequest(session, tokenResponse.getRefreshToken()).asString();
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: refreshTokenResponse: {0}", response);
                if (response.contains("error")) {
                    logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()] Error refreshing token, refresh token expiration?: {0}", response);
                    model.setToken(null);
                    session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
                    event.detail(Details.REASON, "requested_issuer token expired");
                    event.error(Errors.INVALID_TOKEN);
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                String body = extractTokenFromResponse(response, getBodyResponseParameter());
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: refreshTokenResponse body: {0}", body);
                WithingsTokenResponseBody newResponse = JsonSerialization.readValue(body, WithingsTokenResponseBody.class);
                if (newResponse.getExpiresIn() > 0) {
                    int accessTokenExpiration = currentTime + (int) newResponse.getExpiresIn();
                    logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: setting ACCESS_TOKEN_EXPIRATION: {0}", accessTokenExpiration);
                    newResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                }

                if (newResponse.getRefreshToken() == null && tokenResponse.getRefreshToken() != null) {
                    logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: reusing previous refreshToken: {0}", tokenResponse.getRefreshToken());
                    newResponse.setRefreshToken(tokenResponse.getRefreshToken());
                }
                response = JsonSerialization.writeValueAsString(newResponse);

                String oldToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
                if (oldToken != null && oldToken.equals(tokenResponse.getAccessToken())) {
                    int accessTokenExpiration = newResponse.getExpiresIn() > 0 ? currentTime + (int) newResponse.getExpiresIn() : 0;
                    logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: reusing access token with updated expiration: {0}", tokenResponse.getRefreshToken());
                    tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
                    tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
                    tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getAccessToken());
                }
                model.setToken(response);
                tokenResponse = newResponse;
            } else if (exp != null) {
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: expiration of stored token: {0}", exp);
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: current time: {0}", currentTime);
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: setExpiresIn({0})", exp - currentTime);
                tokenResponse.setExpiresIn(exp - currentTime);
            }
            return exchangeTokenResponse(uriInfo, event, authorizedClient, tokenUserSession, tokenResponse);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        logger.debug("[WithingsIdentityProvider::exchangeSessionToken()]");
        String refreshToken = tokenUserSession.getNote(FEDERATED_REFRESH_TOKEN);
        String accessToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
        logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - current access token: {0}", accessToken);
        logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - current refresh token: {0}", refreshToken);

        if (accessToken == null) {
            event.detail(Details.REASON, "SessionToken: requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try {
            long expiration = Long.parseLong(tokenUserSession.getNote(FEDERATED_TOKEN_EXPIRATION));
            logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - FEDERATED_TOKEN_EXPIRATION: {0}", expiration);
            int currentTime = Time.currentTime();
            if (expiration == 0 || expiration > currentTime) {
                logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - expiration == 0 || expiration > {0} => not expired", currentTime);
                WithingsTokenResponseBody tokenResponse = new WithingsTokenResponseBody();
                tokenResponse.setExpiresIn(expiration);
                tokenResponse.setAccessToken(accessToken);
                tokenResponse.setRefreshToken(null);
                tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
                tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
                logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - returning WithingsTokenResponse:  { expiresIn: {0}, accessToken: {1}, otherClaims: [{2}: {3}, {4]: {5}",
                        expiration, accessToken, OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE, ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
                event.success();
                return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
            }
            String response = getRefreshTokenRequest(session, refreshToken).asString();
            logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()]: refreshTokenResponse: {0}", response);
            if (response.contains("error")) {
                logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()] Error refreshing token, refresh token expiration?: {0}", response);
                event.detail(Details.REASON, "requested_issuer token expired");
                event.error(Errors.INVALID_TOKEN);
                return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
            }
            String body = extractTokenFromResponse(response, getBodyResponseParameter());
            logger.debugv("[WithingsIdentityProvider::exchangeStoredToken()]: refreshTokenResponse body: {0}", body);
            WithingsTokenResponseBody newResponse = JsonSerialization.readValue(body, WithingsTokenResponseBody.class);
            long accessTokenExpiration = newResponse.getExpiresIn() > 0 ? currentTime + newResponse.getExpiresIn() : 0;
            tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
            tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
            tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getAccessToken());
            return exchangeTokenResponse(uriInfo, event, authorizedClient, tokenUserSession, newResponse);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Response exchangeTokenResponse(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, WithingsTokenResponseBody response) {
        response.setRefreshToken(null);
        response.getOtherClaims().clear();
        response.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
        response.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
        logger.debugv("[WithingsIdentityProvider::exchangeSessionToken()] - returning 200 -OK with body: {0}", response);
        event.success();
        return Response.ok(response).type(MediaType.APPLICATION_JSON_TYPE).build();
    }


    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        WithingsTokenResponseBody tokenResponse = (WithingsTokenResponseBody) context.getContextData().get(FEDERATED_ACCESS_TOKEN_RESPONSE);
        int currentTime = Time.currentTime();
        long expiration = tokenResponse.getExpiresIn() > 0 ? tokenResponse.getExpiresIn() + currentTime : 0;
        authSession.setUserSessionNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(expiration));
        authSession.setUserSessionNote(FEDERATED_REFRESH_TOKEN, tokenResponse.getRefreshToken());
        authSession.setUserSessionNote(FEDERATED_ACCESS_TOKEN, tokenResponse.getAccessToken());
    }

    private String getBodyResponseParameter() {
        return OAUTH2_PARAMETER_BODY;
    }

    protected String extractTokenFromResponse(String response, String tokenName) {
        if (response == null)
            return null;

        if (response.startsWith("{")) {
            try {
                JsonNode node = mapper.readTree(response);
                if (node.has(tokenName)) {
                    String s;
                    if (OAUTH2_PARAMETER_BODY.equals(tokenName) || OAUTH2_PARAMETER_EXPIRES_IN.equals(tokenName)) {
                        s = node.get(tokenName).toString();
                    } else {
                        s = node.get(tokenName).textValue();
                    }
                    if (s == null || s.trim().isEmpty())
                        return null;
                    return s;
                } else {
                    return null;
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract token [" + tokenName + "] from response [" + response + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(tokenName + "=([^&]+)").matcher(response);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}
