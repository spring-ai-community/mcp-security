/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.authorizationserver.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientRegistrationAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * An {@link AuthenticationConverter} for the client registration endpoint that tolerates
 * empty scopes.
 * <p>
 * Lifted from {@link OAuth2ClientRegistrationAuthenticationConverter}, which is
 * {@code final} and does not allow customizing the underlying
 * {@link OAuth2ClientRegistrationHttpMessageConverter}. The only difference is the
 * injected {@link McpEmptyScopeClientRegistrationConverter}.
 * <p>
 * For internal use only.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://github.com/spring-projects/spring-security/pull/19765">Spring
 * Security #19765</a>
 */
class McpEmptyScopeClientRegistrationAuthenticationConverter implements AuthenticationConverter {

	private final HttpMessageConverter<OAuth2ClientRegistration> clientRegistrationHttpMessageConverter = clientRegistrationHttpMessageConverter();

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();

		OAuth2ClientRegistration clientRegistration;
		try {
			clientRegistration = this.clientRegistrationHttpMessageConverter.read(OAuth2ClientRegistration.class,
					new ServletServerHttpRequest(request));
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"OAuth 2.0 Client Registration Error: " + ex.getMessage(),
					"https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2");
			throw new OAuth2AuthenticationException(error, ex);
		}

		return new OAuth2ClientRegistrationAuthenticationToken(principal, clientRegistration);
	}

	private static HttpMessageConverter<OAuth2ClientRegistration> clientRegistrationHttpMessageConverter() {
		var messageConverter = new OAuth2ClientRegistrationHttpMessageConverter();
		messageConverter.setClientRegistrationConverter(new McpEmptyScopeClientRegistrationConverter());
		return messageConverter;
	}

}
