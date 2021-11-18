package de.helict.keycloak.authentication.authenticators.broker;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
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
    public static final String REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION = "require.password.update.after.registration";
    public static final String CALLBACK_URI_PROPERTY = "user.created.callback.uri";
    public static final String CALLBACK_BODY_PROPERTY = "user.created.callback.body";
    public static final String CALLBACK_HEADER_PROPERTY = "user.created.callback.header";

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
        requirePWUpdateProperty.setName(REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION);
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
    }
}
