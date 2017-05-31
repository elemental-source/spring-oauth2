package org.springframework.security.oauth.examples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.util.Arrays;
import java.util.List;

public class OAuth2AuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private ResourceOwnerPasswordAccessTokenProvider provider;

    private String accessTokenUri;
    private String clientId;
    private String clientSecret;
    private List<String> scope;

    public OAuth2AuthenticationProvider(String accessTokenUri, String clientId, String clientSecret, List<String> scope) {
        this.accessTokenUri = accessTokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        OAuth2AccessToken token = obtainToken(username, password);
        return new OAuth2AuthenticationToken(username, password, Arrays.asList(new SimpleGrantedAuthority("USER")), token);
    }

    private OAuth2AccessToken obtainToken(String username, String password) {
        ResourceOwnerPasswordResourceDetails passwordResourceDetails = new ResourceOwnerPasswordResourceDetails();
        passwordResourceDetails.setUsername(username);
        passwordResourceDetails.setPassword(password);
        passwordResourceDetails.setClientId(clientId);
        passwordResourceDetails.setClientSecret(clientSecret);
        passwordResourceDetails.setScope(scope);
        passwordResourceDetails.setAccessTokenUri(accessTokenUri);
        DefaultAccessTokenRequest defaultAccessTokenRequest = new DefaultAccessTokenRequest();
        OAuth2AccessToken token;
        try {
            token = provider.obtainAccessToken(passwordResourceDetails, defaultAccessTokenRequest);
        } catch (OAuth2AccessDeniedException accessDeniedException) {
            throw new BadCredentialsException("Invalid credentials", accessDeniedException);
        }

        return token;
    }

    public OAuth2AccessToken refreshToken(OAuth2AuthenticationToken authentication) {
        OAuth2AccessToken token = authentication.getOAuth2AccessToken();
        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        BaseOAuth2ProtectedResourceDetails resourceDetails = new BaseOAuth2ProtectedResourceDetails();
        resourceDetails.setClientId(clientId);
        resourceDetails.setClientSecret(clientSecret);
        resourceDetails.setScope(scope);
        resourceDetails.setAccessTokenUri(accessTokenUri);
        OAuth2AccessToken newToken = provider.refreshAccessToken(resourceDetails, refreshToken, new DefaultAccessTokenRequest());
        authentication.setOAuth2AccessToken(newToken);
        return newToken;
    }

    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}