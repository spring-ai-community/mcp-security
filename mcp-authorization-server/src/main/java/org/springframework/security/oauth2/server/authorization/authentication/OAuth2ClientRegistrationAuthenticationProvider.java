/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.converter.RegisteredClientOAuth2ClientRegistrationConverter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Dynamic Client
 * Registration Endpoint.
 *
 * @author Joe Grandja
 * @since 2.0
 * @see OAuth2ClientRegistrationAuthenticationToken
 * @see RegisteredClientRepository
 * @see PasswordEncoder
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3">3. Client
 * Registration Endpoint</a>
 */
public final class OAuth2ClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private Converter<RegisteredClient, OAuth2ClientRegistration> clientRegistrationConverter;

	private Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter;

	private PasswordEncoder passwordEncoder;

	/**
	 * Constructs an {@code OAuth2ClientRegistrationAuthenticationProvider} using the
	 * provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 */
	public OAuth2ClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.clientRegistrationConverter = new RegisteredClientOAuth2ClientRegistrationConverter();
		this.registeredClientConverter = new OAuth2ClientRegistrationRegisteredClientConverter();
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OAuth2ClientRegistrationAuthenticationToken) authentication;

		if (!isValidRedirectUris(clientRegistrationAuthentication.getClientRegistration().getRedirectUris())) {
			throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
					OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client registration request parameters");
		}

		RegisteredClient registeredClient = this.registeredClientConverter
			.convert(clientRegistrationAuthentication.getClientRegistration());

		if (StringUtils.hasText(registeredClient.getClientSecret())) {
			// Encode the client secret
			RegisteredClient updatedRegisteredClient = RegisteredClient.from(registeredClient)
				.clientSecret(this.passwordEncoder.encode(registeredClient.getClientSecret()))
				.build();
			this.registeredClientRepository.save(updatedRegisteredClient);
			if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()
				.equals(clientRegistrationAuthentication.getClientRegistration()
					.getTokenEndpointAuthenticationMethod())) {
				// Return the hashed client_secret
				registeredClient = updatedRegisteredClient;
			}
		}
		else {
			this.registeredClientRepository.save(registeredClient);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved registered client");
		}

		OAuth2ClientRegistration clientRegistration = this.clientRegistrationConverter.convert(registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client registration request");
		}

		return new OAuth2ClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link Converter} used for converting an {@link OAuth2ClientRegistration}
	 * to a {@link RegisteredClient}.
	 * @param registeredClientConverter the {@link Converter} used for converting an
	 * {@link OAuth2ClientRegistration} to a {@link RegisteredClient}
	 */
	public void setRegisteredClientConverter(
			Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter) {
		Assert.notNull(registeredClientConverter, "registeredClientConverter cannot be null");
		this.registeredClientConverter = registeredClientConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting a {@link RegisteredClient} to an
	 * {@link OAuth2ClientRegistration}.
	 * @param clientRegistrationConverter the {@link Converter} used for converting a
	 * {@link RegisteredClient} to an {@link OAuth2ClientRegistration}
	 */
	public void setClientRegistrationConverter(
			Converter<RegisteredClient, OAuth2ClientRegistration> clientRegistrationConverter) {
		Assert.notNull(clientRegistrationConverter, "clientRegistrationConverter cannot be null");
		this.clientRegistrationConverter = clientRegistrationConverter;
	}

	/**
	 * Sets the {@link PasswordEncoder} used to encode the
	 * {@link RegisteredClient#getClientSecret() client secret}. If not set, the client
	 * secret will be encoded using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
	 * @param passwordEncoder the {@link PasswordEncoder} used to encode the client secret
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	private static boolean isValidRedirectUris(List<String> redirectUris) {
		if (CollectionUtils.isEmpty(redirectUris)) {
			return true;
		}

		for (String redirectUri : redirectUris) {
			try {
				URI validRedirectUri = new URI(redirectUri);
				if (validRedirectUri.getFragment() != null) {
					return false;
				}
			}
			catch (URISyntaxException ex) {
				return false;
			}
		}

		return true;
	}

	private static void throwInvalidClientRegistration(String errorCode, String fieldName) {
		OAuth2Error error = new OAuth2Error(errorCode, "Invalid Client Registration: " + fieldName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
