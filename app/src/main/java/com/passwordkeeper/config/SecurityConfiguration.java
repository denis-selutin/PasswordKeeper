package com.passwordkeeper.config;

import com.passwordkeeper.config.security.filter.GoogleOAuth2Filter;
import com.passwordkeeper.config.security.filter.GoogleOauth2AuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.filter.GenericFilterBean;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebMvcSecurity
@EnableGlobalAuthentication
@EnableOAuth2Client
@EnableWebSecurity
@PropertySource("classpath:application.properties")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private Environment env;

    @Resource
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;

    @Autowired
    private OAuth2ClientContextFilter oAuth2ClientContextFilter;

    @Autowired
    private UserDetailsService customUserService;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(googleOauth2AuthProvider());
        super.configure(auth);
    }

    @Bean
    public OAuth2ProtectedResourceDetails googleAuth2ProtectedResourceDetails() {
        AuthorizationCodeResourceDetails auth2ProtectedResourceDetails = new AuthorizationCodeResourceDetails();
        auth2ProtectedResourceDetails.setClientAuthenticationScheme(AuthenticationScheme.form);
        auth2ProtectedResourceDetails.setAuthenticationScheme(AuthenticationScheme.form);

        auth2ProtectedResourceDetails.setGrantType(env.getProperty("google.authorization.code"));
        auth2ProtectedResourceDetails.setClientId(env.getProperty("google.client.id"));
        auth2ProtectedResourceDetails.setClientSecret(env.getProperty("google.client.secret"));
        auth2ProtectedResourceDetails.setAccessTokenUri(env.getProperty("google.accessTokenUri"));
        String commaSeparatedScopes = env.getProperty("google.auth.scope");
        auth2ProtectedResourceDetails.setScope(parseScopes(commaSeparatedScopes));
        auth2ProtectedResourceDetails.setUserAuthorizationUri(env.getProperty("google.userAuthorizationUri"));
        auth2ProtectedResourceDetails.setUseCurrentUri(false);
        auth2ProtectedResourceDetails.setPreEstablishedRedirectUri(env.getProperty("google.preestablished.redirect.url"));
        return auth2ProtectedResourceDetails;
    }

    private List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = new ArrayList();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    @Bean
    public OAuth2RestTemplate oauth2RestTemplate() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(googleAuth2ProtectedResourceDetails(), new DefaultOAuth2ClientContext(accessTokenRequest));
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            // Ignore 400
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 400) {
                    super.handleError(response);
                }
            }
        });
        return restTemplate;
    }

    @Bean
    public GenericFilterBean googleOAuth2Filter() throws Exception {
        GoogleOAuth2Filter googleOAuth2Filter = new GoogleOAuth2Filter(env.getProperty("defaultFilterProcessesUrl"));
        googleOAuth2Filter.setGoogleAuthorizationUrl(env.getProperty("google.userAuthorizationUri"));
        googleOAuth2Filter.setAccessTokenUrl(env.getProperty("google.personDetailUri"));
        googleOAuth2Filter.setAuthenticationManager(authenticationManager());
        return googleOAuth2Filter;
    }

    @Bean
    public AuthenticationProvider googleOauth2AuthProvider() {
        GoogleOauth2AuthProvider googleOauth2AuthProvider = new GoogleOauth2AuthProvider();
        return googleOauth2AuthProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests()
                .antMatchers(HttpMethod.GET, "/login", "/public/**", "/resources/**", "/resources/public/**").permitAll()
                .antMatchers("/google_oauth2_login").anonymous()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/")
                .and().csrf().disable()
                .logout()
                    .logoutSuccessUrl("/")
                    .logoutUrl("/logout")
                .and()
                    .addFilterAfter(oAuth2ClientContextFilter, ExceptionTranslationFilter.class)
                    .addFilterAfter(googleOAuth2Filter(), OAuth2ClientContextFilter.class)
                    .userDetailsService(customUserService);

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/resources/**");
    }

}
