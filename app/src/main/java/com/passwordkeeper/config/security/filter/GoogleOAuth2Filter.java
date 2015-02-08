/**
 * 
 */
package com.passwordkeeper.config.security.filter;

import com.passwordkeeper.model.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class GoogleOAuth2Filter extends AbstractAuthenticationProcessingFilter {

	private static final Authentication dummyAuthentication;

	static {
		dummyAuthentication = new UsernamePasswordAuthenticationToken(
				"dummyUserName23452346789", "dummyPassword54245",
				CustomUserDetails.DEFAULT_ROLES);
	}

	private String googleAuthorizationUrl;
	private String accessTokenUrl;

	public GoogleOAuth2Filter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	private static final String ID = "id";
	private static final String EMAIL = "emails";
	private static final Logger logger = LoggerFactory.getLogger(GoogleOAuth2Filter.class);

	@Autowired
	private OAuth2RestTemplate oauth2RestTemplate;

	private CustomOAuth2AuthenticationToken getOAuth2Token(String email, String id) {
		return new CustomOAuth2AuthenticationToken(new CustomUserDetails(email, id));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,	HttpServletResponse response) throws AuthenticationException,
			IOException, ServletException {
		logger.info("Google Oauth Filter Triggered!!");
		URI authURI;
		try {
			authURI = new URI(googleAuthorizationUrl);
		} catch (URISyntaxException e) {
			logger.error("ERROR WHILE CREATING GOOGLE AUTH URL", e);
			return null;
		}
		SecurityContext context = SecurityContextHolder.getContext();
		String code = request.getParameter("code");
		Map<String, String[]> parameterMap = request.getParameterMap();
		logger.debug(parameterMap.toString());
		if (StringUtils.isEmpty(code)) {
			logger.debug("Will set dummy user in context ");
			context.setAuthentication(dummyAuthentication);
			oauth2RestTemplate.postForEntity(authURI, null, Object.class);
			return null;
		} else {
			logger.debug("Response from Google Recieved !!");
			ResponseEntity<Object> forEntity = oauth2RestTemplate.getForEntity(accessTokenUrl,	Object.class);
			Map<String, Object> profile = (Map<String, Object>) forEntity.getBody();

			String email = String.valueOf(profile.get(EMAIL));
			String id = String.valueOf(profile.get(ID));
			CustomOAuth2AuthenticationToken authenticationToken = getOAuth2Token(email, id);
			authenticationToken.setAuthenticated(false);
			return getAuthenticationManager().authenticate(authenticationToken);
		}
	}

	public void setGoogleAuthorizationUrl(String googleAuthorizationUrl) {
		this.googleAuthorizationUrl = googleAuthorizationUrl;
	}

	public void setAccessTokenUrl(String accessTokenUrl) {
		this.accessTokenUrl = accessTokenUrl;
	}
}
