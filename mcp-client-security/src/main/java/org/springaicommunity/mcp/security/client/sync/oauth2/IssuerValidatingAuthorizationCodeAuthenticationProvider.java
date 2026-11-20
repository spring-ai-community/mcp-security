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

package org.springaicommunity.mcp.security.client.sync.oauth2;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Validates the RFC 9207 {@code iss} parameter of authorization responses before applying
 * the default {@link OAuth2AuthorizationCodeAuthenticationProvider}.
 * <p>
 * If present, the {@code iss} MUST match the issuer of the client registration the
 * authorization code is exchanged with. If the client registration has no issuer, it MUST
 * NOT be present in the response.
 * <p>
 * The issuer comes from the {@link ClientRegistration.ProviderDetails#getIssuerUri()
 * issuer URI} of the client registration, and whether the authorization server advertises
 * {@code authorization_response_iss_parameter_supported} from its
 * {@link ClientRegistration.ProviderDetails#getConfigurationMetadata() configuration
 * metadata}. When it does, {@code iss} MUST be present in the response. Both are
 * available for client registrations built from the authorization server metadata with
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrations#fromIssuerLocation(String)}:
 * dynamically registered clients, CIMD clients, and Spring Boot registrations that set
 * {@code spring.security.oauth2.client.provider.<id>.issuer-uri}. Spring Boot
 * registrations that configure the authorization server endpoints by hand have no issuer:
 * authorization responses that include {@code iss} are rejected. Client registrations
 * that set an issuer without metadata are treated as if the authorization server does not
 * advertise {@code iss} support.
 * <p>
 * Spring Security's {@link OAuth2AuthorizationCodeAuthenticationProvider} does not keep
 * the {@code iss} parameter. It is read from the query string of the
 * {@link OAuth2AuthorizationResponse#getRedirectUri() redirect URI}, so only the
 * {@code query} response mode is supported.
 * <p>
 * Install it on the {@code oauth2Client()} configurer with
 * {@code withObjectPostProcessor(IssuerValidatingAuthorizationCodeAuthenticationProvider.postProcessor())}.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</a>
 */
public final class IssuerValidatingAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

	/**
	 * Error code of the {@link OAuth2AuthorizationException} thrown when the {@code iss}
	 * parameter is invalid.
	 */
	public static final String INVALID_ISS_PARAMETER_ERROR_CODE = "invalid_iss_parameter";

	static final String ISS_PARAMETER_SUPPORTED_METADATA = "authorization_response_iss_parameter_supported";

	private static final Logger log = LoggerFactory
		.getLogger(IssuerValidatingAuthorizationCodeAuthenticationProvider.class);

	private static final String ISS_PARAMETER = "iss";

	private static final String INVALID_ISS_PARAMETER_DESCRIPTION = "The iss parameter of the authorization response is invalid";

	private static final String RFC_9207_URI = "https://www.rfc-editor.org/rfc/rfc9207#section-2.4";

	private final AuthenticationProvider delegate;

	public IssuerValidatingAuthorizationCodeAuthenticationProvider(AuthenticationProvider delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	@Override
	public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authorizationCode) {
			validateIssuer(authorizationCode.getClientRegistration(),
					authorizationCode.getAuthorizationExchange().getAuthorizationResponse());
		}
		return this.delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	/**
	 * An {@link ObjectPostProcessor} that wraps the
	 * {@link OAuth2AuthorizationCodeAuthenticationProvider} created by the
	 * {@code oauth2Client()} configurer. Other objects are returned unchanged.
	 * @return the object post processor
	 */
	public static ObjectPostProcessor<AuthenticationProvider> postProcessor() {
		return new ObjectPostProcessor<AuthenticationProvider>() {
			@Override
			@SuppressWarnings("unchecked")
			public <O extends AuthenticationProvider> O postProcess(O object) {
				if (object instanceof OAuth2AuthorizationCodeAuthenticationProvider) {
					return (O) new IssuerValidatingAuthorizationCodeAuthenticationProvider(object);
				}
				return object;
			}
		};
	}

	private static void validateIssuer(ClientRegistration clientRegistration,
			OAuth2AuthorizationResponse authorizationResponse) {
		var registrationId = clientRegistration.getRegistrationId();
		var providerDetails = clientRegistration.getProviderDetails();
		var issuer = providerDetails.getIssuerUri();
		var values = issParameter(authorizationResponse.getRedirectUri());
		if (!StringUtils.hasText(issuer)) {
			if (!values.isEmpty()) {
				throw invalidIssParameter(
						"The authorization response includes an iss parameter, but client registration ["
								+ registrationId
								+ "] has no issuer to compare it to. Configure the issuer of the client registration, for example with spring.security.oauth2.client.provider.<id>.issuer-uri, or disable iss validation");
			}
			log.debug(
					"Client registration [{}] has no issuer and the authorization response has no iss parameter: the issuer of the authorization response is not validated (RFC 9207)",
					registrationId);
			return;
		}
		var issParameterSupported = Boolean.TRUE
			.equals(providerDetails.getConfigurationMetadata().get(ISS_PARAMETER_SUPPORTED_METADATA));
		if (values.isEmpty()) {
			if (issParameterSupported) {
				throw invalidIssParameter("The authorization server of client registration [" + registrationId
						+ "] advertises the iss parameter, but the authorization response does not include it");
			}
			return;
		}
		if (values.size() > 1) {
			throw invalidIssParameter("The authorization response for client registration [" + registrationId
					+ "] includes more than one iss parameter");
		}
		if (!issuer.equals(values.get(0))) {
			throw invalidIssParameter("The iss parameter of the authorization response does not match the issuer ["
					+ issuer + "] of client registration [" + registrationId + "]");
		}
	}

	/**
	 * Reads the values of the {@code iss} parameter from the query string of the redirect
	 * URI, decoded as {@code application/x-www-form-urlencoded}. Values are not
	 * normalized.
	 */
	private static List<String> issParameter(String redirectUri) {
		var values = UriComponentsBuilder.fromUriString(redirectUri).build().getQueryParams().get(ISS_PARAMETER);
		if (values == null) {
			return List.of();
		}
		// A bare "?iss" without "=" yields a null value, although the type says otherwise
		return values.stream().map(value -> decodeIssParameter(Objects.requireNonNullElse(value, ""))).toList();
	}

	private static String decodeIssParameter(String value) {
		try {
			return URLDecoder.decode(value, StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException ex) {
			throw invalidIssParameter("The iss parameter of the authorization response is not correctly URL-encoded");
		}
	}

	/**
	 * Logs the reason at debug level, and returns an error with a generic description:
	 * the description is sent to the browser in the error redirect, so it must not
	 * include configuration details such as the issuer or the registration id.
	 */
	private static OAuth2AuthorizationException invalidIssParameter(String reason) {
		log.debug("Rejected authorization response (RFC 9207): {}", reason);
		return new OAuth2AuthorizationException(
				new OAuth2Error(INVALID_ISS_PARAMETER_ERROR_CODE, INVALID_ISS_PARAMETER_DESCRIPTION, RFC_9207_URI));
	}

}
