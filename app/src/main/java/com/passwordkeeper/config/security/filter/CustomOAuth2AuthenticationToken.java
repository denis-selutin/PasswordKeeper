/**
 * 
 */
package com.passwordkeeper.config.security.filter;

import com.passwordkeeper.model.CustomUserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomOAuth2AuthenticationToken extends AbstractAuthenticationToken {

	private CustomUserDetails registeredUser;

	public CustomOAuth2AuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	public CustomOAuth2AuthenticationToken(CustomUserDetails registeredUser) {
		super(CustomUserDetails.DEFAULT_ROLES);
		this.registeredUser = registeredUser;
	}

	@Override
	public Object getCredentials() {
		return "NOT_REQUIRED";
	}

	@Override
	public Object getPrincipal() {
		return registeredUser;
	}

	public CustomUserDetails getUserDetail() {
		return registeredUser;
	}

	public void setUserDetail(CustomUserDetails registeredUser) {
		this.registeredUser = registeredUser;
		setDetails(registeredUser);
	}
}
