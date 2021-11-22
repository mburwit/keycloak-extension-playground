package de.helict.keycloak.authentication.authenticators.httppost.handler;

import de.helict.keycloak.authentication.authenticators.httppost.SendHttpPostAuthenticatorFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import static de.helict.keycloak.authentication.authenticators.httppost.handler.HttpPostPreparer.*;

public class HttpPostHandler {

    private static final Logger logger = Logger.getLogger(HttpPostHandler.class);

    public static void handle(
            AuthenticationFlowContext context,
            UserModel registeredUser) {

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        List<String> uris = HttpPostPreparer.parseMultivaluedStringProperty(
                config,
                SendHttpPostAuthenticatorFactory.CALLBACK_URI_PROPERTY,
                registeredUser
        );
        Map<String, String> header = parseMapProperty(
                config,
                SendHttpPostAuthenticatorFactory.CALLBACK_HEADER_PROPERTY,
                registeredUser
        );
        String body = parseTextProperty(
                config,
                SendHttpPostAuthenticatorFactory.CALLBACK_BODY_PROPERTY,
                registeredUser
        );
        if (config != null && Boolean.parseBoolean(config.getConfig().get(SendHttpPostAuthenticatorFactory.AUTH_REQUIRED_PROPERTY))) {
            try {
                header.put("Authorization", issueToken(
                        parseTextProperty(config, SendHttpPostAuthenticatorFactory.AUTH_ENDPOINT_PROPERTY, null),
                        parseAuthBody(config)
                ));
            } catch (IOException e) {
                logger.errorf(
                        e,
                        "Failed to get Authorization header for POSTs after login of user [%s]",
                        registeredUser.getId());
            }
        }
        uris.forEach(uri -> {
            try {
                sendPost(uri, header, body);
            } catch (IOException e) {
                logger.errorf(
                        e,
                        "Failed to POST to callback URI [%s] after first login of user [%s]",
                        uri, registeredUser.getId());
                throw new RuntimeException();
            }
        });
    }

    private static void sendPost(String uri, Map<String, String> header, String body) throws IOException {
        HttpPost post = new HttpPost(URI.create(uri));
        if (header != null) {
            header.forEach(post::addHeader);
        }
        post.setEntity(new ByteArrayEntity(body.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        assert httpClient != null;
        HttpResponse response = httpClient.execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (!String.valueOf(status).startsWith("20")) {
            EntityUtils.consumeQuietly(entity);
            throw new java.io.IOException("Bad status: " + status);
        }
    }

    private static String issueToken(String uri, UrlEncodedFormEntity body) throws IOException {
        HttpPost post = new HttpPost(URI.create(uri));
        post.setEntity(body);

        assert httpClient != null;
        // Create a custom response handler
        ResponseHandler<AccessTokenResponse> responseHandler = response -> {
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                HttpEntity responseEntity = response.getEntity();
                return responseEntity != null ? JsonSerialization.readValue(response.getEntity().getContent(), AccessTokenResponse.class) : null;
            } else {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new ClientProtocolException("Could not issue auth token for sending the POSTs: " + status);
            }
        };
        AccessTokenResponse accessTokenResponse = httpClient.execute(post, responseHandler);
        return accessTokenResponse.getTokenType() + " " + accessTokenResponse.getToken();
    }

    private static final HttpClient httpClient = initHttpClient();

    private static HttpClient initHttpClient() {
        try {
            SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            sslContextBuilder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            return HttpClients.custom().setSSLContext(sslContextBuilder.build()).build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }
}
