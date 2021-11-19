package de.helict.keycloak.authentication.authenticators.broker;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory implements AuthenticatorFactory {
    static IdpCreateUserIfUniqueAndCallbackAuthenticator SINGLETON = new IdpCreateUserIfUniqueAndCallbackAuthenticator();

    private static final Logger logger = Logger.getLogger(IdpCreateUserIfUniqueAndCallbackAuthenticator.class);
    public static final String PROVIDER_ID = "idp-create-user-and-callback";
    public static final String CALLBACK_URI_PROPERTY = "user.created.callback.uri";
    public static final String CALLBACK_BODY_PROPERTY = "user.created.callback.body";
    public static final String CALLBACK_HEADER_PROPERTY = "user.created.callback.header";
    public static final String AUTH_REQUIRED_PROPERTY = "user.created.callback.auth.type";
    public static final String AUTH_ENDPOINT_PROPERTY = "user.created.callback.auth.endpoint";
    public static final String AUTH_CLIENT_ID_PROPERTY = "user.created.callback.auth.client.id";
    public static final String AUTH_CLIENT_SECRET_PROPERTY = "user.created.callback.auth.client.secret";
    public static final String AUTH_SCOPES_PROPERTY = "user.created.callback.auth.client.scopes";

    @Override
    public String getDisplayType() {
        return "Create User If Unique And Callback";
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
        return "Detect if there is existing Keycloak account with same email like identity provider. If no, create new user, and send a POST to a list of callback URIs";
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
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.infof("Initialized...");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty requirePWUpdateProperty;
        requirePWUpdateProperty = new ProviderConfigProperty();
        requirePWUpdateProperty.setName(IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION);
        requirePWUpdateProperty.setLabel("Require Password Update After Registration");
        requirePWUpdateProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        requirePWUpdateProperty.setHelpText("If this option is true and new user is successfully imported from Identity Provider to Keycloak (there is no duplicated email or username detected in Keycloak DB), then this user is required to update his password");
        configProperties.add(requirePWUpdateProperty);

        ProviderConfigProperty callbackUrisProperty;
        callbackUrisProperty = new ProviderConfigProperty();
        callbackUrisProperty.setName(CALLBACK_URI_PROPERTY);
        callbackUrisProperty.setLabel("Callback Uris");
        callbackUrisProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        callbackUrisProperty.setHelpText("If new user is successfully imported from Identity Provider to Keycloak (there is no duplicated email or username detected in Keycloak DB), then Keycloak will send a POST with the created user id to these URIs");
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
        authRequiredProperty.setLabel("POSTS require Keycloak Auth");
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
