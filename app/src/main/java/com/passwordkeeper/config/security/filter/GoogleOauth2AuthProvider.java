/**
 * 
 */
package com.passwordkeeper.config.security.filter;

import com.passwordkeeper.model.CustomUserDetails;
import com.passwordkeeper.service.CustomUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class GoogleOauth2AuthProvider implements AuthenticationProvider {

	private static final Logger logger = LoggerFactory.getLogger(GoogleOauth2AuthProvider.class);

	@Autowired(required = true)
	private CustomUserService userService;

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		logger.info("Provider Manager Executed ?!!");
		CustomOAuth2AuthenticationToken token = (CustomOAuth2AuthenticationToken) authentication;
		CustomUserDetails registeredUser = (CustomUserDetails) token.getPrincipal();
		registeredUser = (CustomUserDetails) userService.loadUserByUsername(registeredUser.getUsername());
		token = new CustomOAuth2AuthenticationToken(registeredUser);
		token.setAuthenticated(true);
		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return CustomOAuth2AuthenticationToken.class.isAssignableFrom(authentication);
	}
}
