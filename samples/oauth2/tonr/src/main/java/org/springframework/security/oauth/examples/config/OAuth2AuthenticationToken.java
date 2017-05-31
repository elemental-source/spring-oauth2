package org.springframework.security.oauth.examples.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Collection;

/**
 * @author paul.wheeler
 */
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {

    private Object credential;
    private Object principal;
    private String redirectUri;
    private OAuth2AccessToken oAuth2AccessToken;

    public OAuth2AuthenticationToken(Object credential) {
        super(null);
        this.credential = credential;
        setAuthenticated(false);
    }

    public OAuth2AuthenticationToken(Object principal, Object credential,
                                     Collection<? extends GrantedAuthority> authorities,
                                     OAuth2AccessToken oAuth2AccessToken) {
        super(authorities);
        this.credential = credential;
        this.principal = principal;
        this.oAuth2AccessToken = oAuth2AccessToken;
        setAuthenticated(true);
    }

    /**
     * The credentials that prove the principal is correct. This will be either an OAuth2 code from the OAuth2
     * provider, or will be an OAuth2 token once the code has been exchanged for a token from the OAuth2 provider.
     * Whilst not particularly clean, that seems to fit Spring Security best.
     *
     * @return the credentials that prove the identity of the <code>Principal</code>
     */
    @Override
    public Object getCredentials() {
        return credential;
    }

    /**
     * The identity of the principal being authenticated. In the case of an authentication request with username and
     * password, this would be the username. Callers are expected to populate the principal for an authentication
     * request.
     * <p/>
     * The <tt>AuthenticationManager</tt> implementation will often return an <tt>Authentication</tt> containing
     * richer information as the principal for use by the application. Many of the authentication providers will
     * create a {@code UserDetails} object as the principal.
     *
     * @return the <code>Principal</code> being authenticated or the authenticated principal after authentication.
     */
    @Override
    public Object getPrincipal() {
        return principal;
    }

    /**
     * Gets the redirect URI where this authentication token response should be sent
     *
     * @return redirectUri as an absolute URI in string form or null
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets the redirect URI where this authentication token response should be sent
     *
     * @param redirectUri an absolute URI in string form or null
     */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public OAuth2AccessToken getOAuth2AccessToken() {
        return oAuth2AccessToken;
    }

    public void setOAuth2AccessToken(OAuth2AccessToken oAuth2AccessToken) {
        this.oAuth2AccessToken = oAuth2AccessToken;
    }
}