package de.helict.keycloak.authentication.authenticators.httppost;

import de.helict.keycloak.authentication.authenticators.httppost.handler.HttpPostHandler;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class SendHttpPostAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpPostHandler.handle(context, context.getUser());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // none
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // none
    }

    @Override
    public void close() {
        // none
    }
}
