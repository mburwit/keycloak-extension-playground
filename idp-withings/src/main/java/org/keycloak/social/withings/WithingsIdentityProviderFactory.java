package org.keycloak.social.withings;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class WithingsIdentityProviderFactory extends AbstractIdentityProviderFactory<WithingsIdentityProvider>
        implements SocialIdentityProviderFactory<WithingsIdentityProvider> {

    public static final String PROVIDER_ID = "withings";

    @Override
    public String getName() {
        return "Withings";
    }

    @Override
    public WithingsIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WithingsIdentityProvider(session, new WithingsIdentityProviderConfig(model));
    }

    @Override
    public WithingsIdentityProviderConfig createConfig() {
        return new WithingsIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}