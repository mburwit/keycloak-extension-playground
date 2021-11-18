package org.keycloak.social.withings;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WithingsIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public WithingsIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public WithingsIdentityProviderConfig() {
    }
}
