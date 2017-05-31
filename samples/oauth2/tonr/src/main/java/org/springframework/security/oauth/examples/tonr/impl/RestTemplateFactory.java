package org.springframework.security.oauth.examples.tonr.impl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

import java.util.Arrays;

public class RestTemplateFactory {

    @Value("${accessTokenUri}")
    private String accessTokenUri;

    private OAuth2ClientContext oAuth2ClientContext;

    public OAuth2RestOperations create() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = ((User) authentication.getPrincipal()).getUsername();
        String password = (String) authentication.getCredentials();
        return new OAuth2RestTemplate(createResourceDetails(username, password), oAuth2ClientContext);
    }

    private ResourceOwnerPasswordResourceDetails createResourceDetails(String username, String password) {
        ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
        resourceDetails.setAccessTokenUri(accessTokenUri);
        resourceDetails.setClientId("my-trusted-client-with-secret");
        resourceDetails.setClientSecret("somesecret");
        resourceDetails.setAccessTokenUri(accessTokenUri);
        resourceDetails.setScope(Arrays.asList("read", "write"));
        resourceDetails.setUsername(username);
        resourceDetails.setPassword(password);
        return resourceDetails;
    }

    public void setOAuth2ClientContext(OAuth2ClientContext oAuth2ClientContext) {
        this.oAuth2ClientContext = oAuth2ClientContext;
    }

}
