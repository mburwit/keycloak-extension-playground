package demo.keycloak.oidcmappers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.Resteasy;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserPropertyMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.IDToken;
import org.keycloak.services.Urls;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * <pre>{@code
 *
 * KC_ISSUER=http://localhost:8081/auth/realms/remote-claims
 * KC_CLIENT_ID=demo-client-remote-claims
 * KC_USERNAME=tester
 * KC_PASSWORD=test
 *
 * KC_RESPONSE=$( \
 * curl \
 *   -d "client_id=$KC_CLIENT_ID" \
 *   -d "username=$KC_USERNAME" \
 *   -d "password=$KC_PASSWORD" \
 *   -d "grant_type=password" \
 *   "$KC_ISSUER/protocol/openid-connect/token" \
 * )
 * echo $KC_RESPONSE | jq -C .
 *
 * }</pre>
 */
@JBossLog
@AutoService(ProtocolMapper.class)
public class RemoteOidcMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "oidc-remote-protocol-mapper";

    private static final Logger LOGGER = Logger.getLogger(RemoteOidcMapper.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    private static final String REMOTE_URL_PROPERTY = "remoteUrl";

    public static final String DEFAULT_REMOTE_CLAIM_URL = "http://localhost:7777/claims?userId={userId}&username={username}&clientId={clientId}&issuer={issuer}";

    public static final String ROOT_OBJECT = "$ROOT$";

    static {

        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(REMOTE_URL_PROPERTY)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Remote URL")
                .helpText("URL to fetch custom claims for the given user")
                .defaultValue(DEFAULT_REMOTE_CLAIM_URL)
                .add()
                .build();

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, UserPropertyMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Demo Remote Mapper";
    }

    @Override
    public String getHelpText() {
        return "A protocol mapper that can fetch additional claims from an external service";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        HttpServletRequest httpRequest = Resteasy.getContextData(HttpServletRequest.class);
        // extract information from httpRequest

        KeycloakContext context = keycloakSession.getContext();
        boolean userInfoEndpointRequest = context.getUri().getPath().endsWith("/userinfo");

        String issuer = token.getIssuedFor();
        String clientId = token.getIssuedFor();
        if (userInfoEndpointRequest) {
            clientId = context.getClient().getClientId();
            issuer = Urls.realmIssuer(context.getUri().getBaseUri(), context.getRealm().getName());
        }

        Object claimValue = fetchRemoteClaims(mappingModel, userSession, keycloakSession, issuer, clientId);
        LOGGER.infof("setClaim %s=%s", mappingModel.getName(), claimValue);

        String claimName = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        if (ROOT_OBJECT.equals(claimName) && claimValue instanceof ObjectNode) {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> values = mapper.convertValue(claimValue, new TypeReference<Map<String, Object>>() {
            });
            token.getOtherClaims().putAll(values);
            return;
        }

        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
    }

    private Object fetchRemoteClaims(ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, String issuer, String clientId) {

        try {
            String remoteUrlTemplate = mappingModel.getConfig().getOrDefault(REMOTE_URL_PROPERTY, DEFAULT_REMOTE_CLAIM_URL);
            UserModel user = userSession.getUser();
            String url = UriBuilder.fromUri(remoteUrlTemplate).build(user.getId(), user.getUsername(), clientId, issuer).toString();
            return SimpleHttp.doGet(url, keycloakSession).asJson();
        } catch (IOException e) {
            log.warn("Could not fetch remote claims for user", e);
        }

        return null;
    }
}