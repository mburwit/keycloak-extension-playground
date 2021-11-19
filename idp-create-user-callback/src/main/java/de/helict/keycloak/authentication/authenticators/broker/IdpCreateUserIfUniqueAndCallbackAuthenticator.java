package de.helict.keycloak.authentication.authenticators.broker;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
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

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        List<String> uris = parseMultivaluedStringProperty(
                config,
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_URI_PROPERTY,
                registeredUser
        );
        Map<String, String> header = parseMapProperty(
                config,
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_HEADER_PROPERTY,
                registeredUser
        );
        String body = parseTextProperty(
                config,
                IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.CALLBACK_BODY_PROPERTY,
                registeredUser
        );
        if (config != null && Boolean.parseBoolean(config.getConfig().get(IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.AUTH_REQUIRED_PROPERTY))) {
            try {
                header.put("Authorization", issueToken(
                        parseTextProperty(config, IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.AUTH_ENDPOINT_PROPERTY, null),
                        parseAuthBody(config)
                ));
            } catch (IOException e) {
                logger.errorf(
                        e,
                        "Failed to get Authorization header for POSTs after first login of user [%s] by ID provider [%s]",
                        registeredUser.getId(), brokerContext.getIdpConfig().getAlias());
            }
        }
        uris.forEach(uri -> {
            try {
                doPostFirstLoginSuccess(uri, header, body);
            } catch (IOException e) {
                logger.errorf(
                        e,
                        "Failed to POST to callback URI [%s] after first login of user [%s] by ID provider [%s]",
                        uri, registeredUser.getId(), brokerContext.getIdpConfig().getAlias());
                throw new RuntimeException();
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

    private String issueToken(String uri, UrlEncodedFormEntity body) throws IOException {
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

    private UrlEncodedFormEntity parseAuthBody(AuthenticatorConfigModel config) throws UnsupportedEncodingException {

        List<NameValuePair> nameValuePairs = new ArrayList<>(4);
        nameValuePairs.add(new BasicNameValuePair("grant_type", URLEncoder.encode(
                "client_credentials", StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("client_id", URLEncoder.encode(
                parseTextProperty(config, IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.AUTH_CLIENT_ID_PROPERTY, null), StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("client_secret", URLEncoder.encode(
                parseTextProperty(config, IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.AUTH_CLIENT_SECRET_PROPERTY, null), StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("scope", URLEncoder.encode(
                parseTextProperty(config, IdpCreateUserIfUniqueAndCallbackAuthenticatorFactory.AUTH_SCOPES_PROPERTY, null), StandardCharsets.UTF_8)));
        return new UrlEncodedFormEntity(nameValuePairs, Consts.UTF_8);
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
        if (registeredUser != null) {
            result = result.replaceAll("\\$\\{user.id}", registeredUser.getId());
        }
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
