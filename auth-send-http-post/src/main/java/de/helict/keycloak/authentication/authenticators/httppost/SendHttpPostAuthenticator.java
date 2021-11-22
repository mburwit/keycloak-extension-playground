package de.helict.keycloak.authentication.authenticators.httppost;

import de.helict.keycloak.authentication.authenticators.httppost.handler.HttpPostHandler;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.Response;

public class SendHttpPostAuthenticator implements Authenticator {

    // clientSession.note flag specifies if we created a new patient for this user (true) or not (false)
    public static final String NEW_USER_PATIENT_CREATED = "NEW_USER_PATIENT_CREATED";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            HttpPostHandler.handle(context, context.getUser());
            context.getAuthenticationSession().setAuthNote(NEW_USER_PATIENT_CREATED, "true");
            context.success();
        } catch (Exception e) {
            if (context.getExecution().isRequired()) {
                Response challengeResponse = context.form()
                        .setError(Messages.INTERNAL_SERVER_ERROR)
                        .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
                context.challenge(challengeResponse);
                context.getEvent()
                        .user(context.getUser().getId())
                        .detail("failed_send_post_for_user", context.getUser().getId())
                        .removeDetail(Details.AUTH_METHOD)
                        .removeDetail(Details.AUTH_TYPE)
                        .error(Errors.IDENTITY_PROVIDER_ERROR);
            } else {
                context.attempted();
            }
        }
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
