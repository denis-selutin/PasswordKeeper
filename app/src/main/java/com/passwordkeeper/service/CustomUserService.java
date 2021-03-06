/**
 * 
 */
package com.passwordkeeper.service;

import com.passwordkeeper.model.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserService implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(CustomUserService.class);

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		return new CustomUserDetails("test", "test");
	}

}
