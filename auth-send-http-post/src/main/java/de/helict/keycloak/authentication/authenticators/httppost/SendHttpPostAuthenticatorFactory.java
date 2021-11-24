package de.helict.keycloak.authentication.authenticators.httppost;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class SendHttpPostAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "send-http-post";
    public static final String CALLBACK_URI_PROPERTY = "send.http.post.uri";
    public static final String CALLBACK_BODY_PROPERTY = "send.http.post.body";
    public static final String CALLBACK_HEADER_PROPERTY = "send.http.post.header";
    public static final String AUTH_REQUIRED_PROPERTY = "send.http.post.auth.type";
    public static final String AUTH_ENDPOINT_PROPERTY = "send.http.post.auth.endpoint";
    public static final String AUTH_CLIENT_ID_PROPERTY = "send.http.post.auth.client.id";
    public static final String AUTH_CLIENT_SECRET_PROPERTY = "send.http.post.auth.client.secret";
    public static final String AUTH_SCOPES_PROPERTY = "send.http.post.auth.client.scopes";

    @Override
    public String getDisplayType() {
        return "Send HTTP POST";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Send a POST to a list of URIs";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new SendHttpPostAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty callbackUrisProperty;
        callbackUrisProperty = new ProviderConfigProperty();
        callbackUrisProperty.setName(CALLBACK_URI_PROPERTY);
        callbackUrisProperty.setLabel("URIs");
        callbackUrisProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        callbackUrisProperty.setHelpText("HTTP POST will be sent to these URIs");
        configProperties.add(callbackUrisProperty);

        ProviderConfigProperty bodyProperty;
        bodyProperty = new ProviderConfigProperty();
        bodyProperty.setName(CALLBACK_BODY_PROPERTY);
        bodyProperty.setLabel("POST Body");
        bodyProperty.setType(ProviderConfigProperty.TEXT_TYPE);
        bodyProperty.setHelpText("This will be the request body of the POST, sent to each URI.");
        configProperties.add(bodyProperty);

        ProviderConfigProperty httpHeaderProperty;
        httpHeaderProperty = new ProviderConfigProperty();
        httpHeaderProperty.setName(CALLBACK_HEADER_PROPERTY);
        httpHeaderProperty.setLabel("Http Header");
        httpHeaderProperty.setType(ProviderConfigProperty.MAP_TYPE);
        httpHeaderProperty.setHelpText("Specify key value pairs that will be added as http headers for each POST.");
        configProperties.add(httpHeaderProperty);

        ProviderConfigProperty authRequiredProperty;
        authRequiredProperty = new ProviderConfigProperty();
        authRequiredProperty.setName(AUTH_REQUIRED_PROPERTY);
        authRequiredProperty.setLabel("Authentication required?");
        authRequiredProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        authRequiredProperty.setHelpText("If enabled, Keycloak acts as Keycloak client and retrieves a token by the endpoint specified below, which will then be used as bearer authentication for the POSTs");
        configProperties.add(authRequiredProperty);

        ProviderConfigProperty authTokenEndpoint;
        authTokenEndpoint = new ProviderConfigProperty();
        authTokenEndpoint.setName(AUTH_ENDPOINT_PROPERTY);
        authTokenEndpoint.setLabel("Token Endpoint");
        authTokenEndpoint.setType(ProviderConfigProperty.STRING_TYPE);
        authTokenEndpoint.setHelpText("The token endpoint, Keycloak will get an access token from");
        configProperties.add(authTokenEndpoint);

        ProviderConfigProperty authClientId;
        authClientId = new ProviderConfigProperty();
        authClientId.setName(AUTH_CLIENT_ID_PROPERTY);
        authClientId.setLabel("Client ID");
        authClientId.setType(ProviderConfigProperty.STRING_TYPE);
        authClientId.setHelpText("The client id, Keycloak will use to get an access token");
        configProperties.add(authClientId);

        ProviderConfigProperty authClientSecret;
        authClientSecret = new ProviderConfigProperty();
        authClientSecret.setName(AUTH_CLIENT_SECRET_PROPERTY);
        authClientSecret.setLabel("Client Secret");
        authClientSecret.setType(ProviderConfigProperty.PASSWORD);
        authClientSecret.setHelpText("The client secret, Keycloak will use to get an access token");
        configProperties.add(authClientSecret);

        ProviderConfigProperty authScopes;
        authScopes = new ProviderConfigProperty();
        authScopes.setName(AUTH_SCOPES_PROPERTY);
        authScopes.setLabel("Scopes");
        authScopes.setType(ProviderConfigProperty.STRING_TYPE);
        authScopes.setHelpText("The scopes, Keycloak will get an access token for. Separate multiple scopes with comma");
        configProperties.add(authScopes);
    }
}
