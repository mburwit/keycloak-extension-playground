package de.helict.keycloak.authentication.authenticators.broker;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class IdpCreateUserIfUniqueAndCallbackAuthenticator extends IdpCreateUserIfUniqueAuthenticator {

    private static final Logger logger = Logger.getLogger(IdpCreateUserIfUniqueAndCallbackAuthenticator.class);

    @Override
    protected void userRegisteredSuccess(
            AuthenticationFlowContext context,
            UserModel registeredUser,
            SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {

        List<String> uris = parseMultivaluedStringProperty(
                context.getAuthenticatorConfig(),
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_URI_PROPERTY,
                registeredUser
        );
        Map<String, String> header = parseMapProperty(
                context.getAuthenticatorConfig(),
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_HEADER_PROPERTY,
                registeredUser
        );
        String body = parseTextProperty(
                context.getAuthenticatorConfig(),
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_BODY_PROPERTY,
                registeredUser
        );
        uris.forEach(uri -> {
            try {
                doPostFirstLoginSuccess(uri, header, body);
            } catch (IOException e) {
                logger.errorf(
                        e,
                        "Failed to POST to callback URI [%s] after first login of user [%s] by ID provider [%s]",
                        uri, registeredUser.getId(), brokerContext.getIdpConfig().getAlias());
            }
        });
    }

    protected void doPostFirstLoginSuccess(String uri, Map<String, String> header, String body) throws IOException {
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

    private Map<String, String> parseMapProperty(AuthenticatorConfigModel config,
                                                 String propertyName,
                                                 UserModel registeredUser) {
        if (config != null) {
            String headerMap = replaceVariables(
                    config.getConfig().getOrDefault(
                            propertyName,
                            "[]"
                    ), registeredUser);
            try {
                List<StringPair> map = JsonSerialization.readValue(headerMap, MAP_TYPE_REPRESENTATION);
                return map.stream().collect(Collectors.toMap(StringPair::getKey, StringPair::getValue));
            } catch (IOException e) {
                throw new RuntimeException("Could not deserialize json: " + headerMap, e);
            }
        }
        return Collections.emptyMap();
    }

    private String parseTextProperty(
            AuthenticatorConfigModel config,
            String propertyName,
            UserModel registeredUser) {

        String result = "";
        if (config != null) {
            result = config.getConfig().getOrDefault(
                    propertyName,
                    ""
            );
        }
        return replaceVariables(result, registeredUser);
    }

    private String replaceVariables(String result, UserModel registeredUser) {
        result = result.replaceAll("\\$\\{user.id}", registeredUser.getId());
        return result;
    }

    private List<String> parseMultivaluedStringProperty(
            AuthenticatorConfigModel config,
            String propertyName,
            UserModel registeredUser) {

        List<String> values = new ArrayList<>();
        if (config != null) {
            String list = replaceVariables(
                    config.getConfig().getOrDefault(
                            propertyName,
                            ""
                    ),
                    registeredUser);
            if (list.length() > 0) {
                values = Arrays.asList(list.split("##"));
            }
        }
        return values;
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

    private static final TypeReference<List<StringPair>> MAP_TYPE_REPRESENTATION = new TypeReference<>() {
    };

    static class StringPair {
        String key;
        String value;

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }
    }

}
