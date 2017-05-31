package org.springframework.security.oauth.examples.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${oauth2.accessTokenUri}")
	private String accessTokenUri;

	@Value("${oauth2.clientId}")
	private String clientId;

	@Value("${oauth2.clientSecret}")
	private String clientSecret;

	@Value("#{'${oauth2.scopes}'.split(',')}")
	private List<String> scopes;

	@Bean
	public OAuth2AuthenticationProvider oAuth2AuthenticationProvider() {
		return new OAuth2AuthenticationProvider(accessTokenUri, clientId, clientSecret, scopes);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(oAuth2AuthenticationProvider());
//		auth.inMemoryAuthentication().withUser("marissa").password("wombat").roles("USER").and().withUser("sam")
//				.password("kangaroo").roles("USER");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
    	    http.authorizeRequests()
                .antMatchers("/sparklr/**","/facebook/**").hasRole("USER")
                .anyRequest().permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/login.jsp")
                .permitAll()
                .and()
            .formLogin()
            	.loginProcessingUrl("/login")
                .loginPage("/login.jsp")
				.passwordParameter("password")
				.usernameParameter("username")
                .failureUrl("/login.jsp?authentication_error=true")
                .permitAll();
    	// @formatter:on
	}

}
