package org.keycloak.social.withings;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WithingsIdentityProvider extends AbstractOAuth2IdentityProvider<WithingsIdentityProviderConfig>
        implements SocialIdentityProvider<WithingsIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(WithingsIdentityProvider.class);

    public static final String OAUTH2_PARAMETER_ACTION = "action";
    public static final String OAUTH2_PARAMETER_BODY = "body";
    public static final String OAUTH2_PARAMETER_USER_ID = "userid";
    public static final String OAUTH2_PARAMETER_REFRESH_TOKEN = "refresh_token";
    public static final String OAUTH2_PARAMETER_EXPIRES_IN = "expires_in";

    public static final String AUTH_URL = "https://account.withings.com/oauth2_user/authorize2";
    public static final String TOKEN_URL = "https://wbsapi.withings.net/v2/oauth2";
    public static final String DEFAULT_SCOPE = "user.info,user.activity,user.metrics";
    public static final String ACTION_REQUEST_TOKEN = "requesttoken";

    public WithingsIdentityProvider(KeycloakSession session, WithingsIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setDefaultScope(DEFAULT_SCOPE);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new WithingsEndpoint(callback, realm, event);
    }

    protected SimpleHttp getRefreshTokenRequest(KeycloakSession session, String refreshToken, String clientId, String clientSecret) {
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
        String userId = extractTokenFromResponse(body, getUserIdResponseParameter());
        if (userId == null) {
            throw new IdentityBrokerException("No userId available in OAuth server response: " + response);
        }
        String accessToken = extractTokenFromResponse(body, getAccessTokenResponseParameter());
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }
        String refreshToken = extractTokenFromResponse(body, getRefreshTokenResponseParameter());
        if (refreshToken == null) {
            throw new IdentityBrokerException("No refresh token available in OAuth server response: " + response);
        }
        int expiresIn = 0;
        try {
            expiresIn = Integer.parseInt(extractTokenFromResponse(body, getExpiresInResponseParameter()));
        } catch (NumberFormatException ignored) {
        }
        String scope = extractTokenFromResponse(body, getScopeResponseParameter());
        if (scope == null) {
            throw new IdentityBrokerException("No scope available in OAuth server response: " + response);
        }
        BrokeredIdentityContext context = new BrokeredIdentityContext(userId);
        log.info(Base64.encodeBytes(body.getBytes(StandardCharsets.UTF_8)));
        context.setToken(Base64.encodeBytes(body.getBytes(StandardCharsets.UTF_8)));
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        context.getContextData().put(FEDERATED_REFRESH_TOKEN, refreshToken);
        context.getContextData().put(OIDCIdentityProvider.ACCESS_TOKEN_EXPIRATION, expiresIn > 0 ? Time.currentTime() + expiresIn : 0);
        context.getContextData().put(OAUTH2_PARAMETER_SCOPE, scope);
        context.setIdp(this);
        context.setUsername(getConfig().getAlias() + "-" + userId);

        return context;
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        try {
            return Response.ok(new String(Base64.decode(identity.getToken()))).build();
        } catch (IOException e) {
            log.error(e);
            return null;
        }
    }

    private String getBodyResponseParameter() {
        return OAUTH2_PARAMETER_BODY;
    }

    private String getScopeResponseParameter() {
        return OAUTH2_PARAMETER_SCOPE;
    }

    private String getExpiresInResponseParameter() {
        return OAUTH2_PARAMETER_EXPIRES_IN;
    }

    private String getUserIdResponseParameter() {
        return OAUTH2_PARAMETER_USER_ID;
    }

    protected String getRefreshTokenResponseParameter() {
        return OAUTH2_PARAMETER_REFRESH_TOKEN;
    }

    protected String extractTokenFromResponse(String response, String tokenName) {
        if (response == null)
            return null;

        if (response.startsWith("{")) {
            try {
                JsonNode node = mapper.readTree(response);
                if (node.has(tokenName)) {
                    if (OAUTH2_PARAMETER_BODY.equals(tokenName)) {
                        String s = node.get(tokenName).toString();
                        if (s == null || s.trim().isEmpty())
                            return null;
                        return s;
                    }
                    String s = node.get(tokenName).textValue();
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
