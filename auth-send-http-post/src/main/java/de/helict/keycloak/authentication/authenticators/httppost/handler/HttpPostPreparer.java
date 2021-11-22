package de.helict.keycloak.authentication.authenticators.httppost.handler;

import com.fasterxml.jackson.core.type.TypeReference;
import de.helict.keycloak.authentication.authenticators.httppost.SendHttpPostAuthenticatorFactory;
import org.apache.http.Consts;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class HttpPostPreparer {

    static UrlEncodedFormEntity parseAuthBody(AuthenticatorConfigModel config) {
        List<NameValuePair> nameValuePairs = new ArrayList<>(4);
        nameValuePairs.add(new BasicNameValuePair("grant_type", URLEncoder.encode(
                "client_credentials", StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("client_id", URLEncoder.encode(
                parseTextProperty(config, SendHttpPostAuthenticatorFactory.AUTH_CLIENT_ID_PROPERTY, null), StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("client_secret", URLEncoder.encode(
                parseTextProperty(config, SendHttpPostAuthenticatorFactory.AUTH_CLIENT_SECRET_PROPERTY, null), StandardCharsets.UTF_8)));
        nameValuePairs.add(new BasicNameValuePair("scope", URLEncoder.encode(
                parseTextProperty(config, SendHttpPostAuthenticatorFactory.AUTH_SCOPES_PROPERTY, null), StandardCharsets.UTF_8)));
        return new UrlEncodedFormEntity(nameValuePairs, Consts.UTF_8);
    }

    static Map<String, String> parseMapProperty(AuthenticatorConfigModel config,
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

    static String parseTextProperty(
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

    static String replaceVariables(String result, UserModel registeredUser) {
        if (registeredUser != null) {
            result = result.replaceAll("\\$\\{user.id}", registeredUser.getId());
        }
        return result;
    }

    static List<String> parseMultivaluedStringProperty(
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
