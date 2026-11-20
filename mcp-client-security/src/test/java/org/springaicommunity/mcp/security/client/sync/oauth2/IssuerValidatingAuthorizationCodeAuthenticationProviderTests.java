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

import java.util.HashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.springaicommunity.mcp.security.client.sync.oauth2.IssuerValidatingAuthorizationCodeAuthenticationProvider.INVALID_ISS_PARAMETER_ERROR_CODE;

/**
 * @author Daniel Garnier-Moiroux
 */
class IssuerValidatingAuthorizationCodeAuthenticationProviderTests {

	private static final String ISSUER = "http://localhost:8080";

	private static final String REDIRECT_URI = "http://localhost:9090/authorize/oauth2/code/test";

	private final RecordingAuthenticationProvider delegate = new RecordingAuthenticationProvider();

	private final IssuerValidatingAuthorizationCodeAuthenticationProvider provider = new IssuerValidatingAuthorizationCodeAuthenticationProvider(
			this.delegate);

	@Test
	void advertisedAndMatchingIss() {
		var token = token(true, "?code=code&state=state&iss=http%3A%2F%2Flocalhost%3A8080");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
		assertThat(this.delegate.called).isTrue();
	}

	@Test
	void advertisedAndMissingIss() {
		var token = token(true, "?code=code&state=state");

		assertRejected(token);
	}

	@Test
	void advertisedAndWrongIss() {
		var token = token(true, "?code=code&state=state&iss=https%3A%2F%2Fevil.example.com");

		assertRejected(token);
	}

	@Test
	void notAdvertisedAndMissingIss() {
		var token = token(false, "?code=code&state=state");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
		assertThat(this.delegate.called).isTrue();
	}

	@Test
	void notAdvertisedAndMatchingIss() {
		var token = token(false, "?code=code&state=state&iss=http%3A%2F%2Flocalhost%3A8080");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
		assertThat(this.delegate.called).isTrue();
	}

	@Test
	void notAdvertisedAndWrongIss() {
		var token = token(false, "?code=code&state=state&iss=https%3A%2F%2Fevil.example.com");

		assertRejected(token);
	}

	@Test
	void unencodedMatchingIss() {
		var token = token(true, "?code=code&state=state&iss=http://localhost:8080");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
	}

	@Test
	void issWithTrailingSlash() {
		var token = token(true, "?code=code&state=state&iss=http%3A%2F%2Flocalhost%3A8080%2F");

		assertRejected(token);
	}

	@Test
	void issWithDifferentCase() {
		var token = token(true, "?code=code&state=state&iss=HTTP%3A%2F%2FLOCALHOST%3A8080");

		assertRejected(token);
	}

	@Test
	void issWithDefaultPort() {
		var token = token("https://example.com", true, "?code=code&state=state&iss=https%3A%2F%2Fexample.com%3A443");

		assertRejected(token);
	}

	@Test
	void repeatedIss() {
		var token = token(true,
				"?code=code&state=state&iss=http%3A%2F%2Flocalhost%3A8080&iss=http%3A%2F%2Flocalhost%3A8080");

		assertRejected(token);
	}

	@Test
	void emptyIss() {
		var token = token(false, "?code=code&state=state&iss=");

		assertRejected(token);
	}

	@Test
	void issWithoutValue() {
		var token = token(false, "?code=code&state=state&iss");

		assertRejected(token);
	}

	@Test
	void malformedIss() {
		var token = token(false, "?code=code&state=state&iss=%zz");

		assertRejected(token);
	}

	@Test
	void malformedOtherParameterIsIgnored() {
		var token = token(false, "?code=code&state=state&%zz=value");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
	}

	@Test
	void issInFragmentIsIgnored() {
		var token = token(true, "?code=code&state=state#iss=http%3A%2F%2Flocalhost%3A8080");

		assertRejected(token);
	}

	@Test
	void noIssuerAndIss() {
		var token = token(clientRegistration(null, Map.of()),
				"?code=code&state=state&iss=http%3A%2F%2Flocalhost%3A8080");

		assertRejected(token);
	}

	@Test
	void noIssuerAndNoIss() {
		var token = token(clientRegistration(null, Map.of()), "?code=code&state=state");

		assertThat(this.provider.authenticate(token)).isSameAs(token);
		assertThat(this.delegate.called).isTrue();
	}

	@Test
	void errorResponseWithWrongIss() {
		var authorizationResponse = OAuth2AuthorizationResponse.error("access_denied")
			.errorDescription("from the attacker")
			.state("state")
			.redirectUri(REDIRECT_URI + "?error=access_denied&state=state&iss=https%3A%2F%2Fevil.example.com")
			.build();
		var token = new OAuth2AuthorizationCodeAuthenticationToken(clientRegistration(ISSUER, issSupported(true)),
				new OAuth2AuthorizationExchange(authorizationRequest(), authorizationResponse));

		assertRejected(token);
	}

	@Test
	void wrapsSpringSecurityProvider() {
		@SuppressWarnings("unchecked")
		var springProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
				mock(OAuth2AccessTokenResponseClient.class));

		AuthenticationProvider postProcessed = IssuerValidatingAuthorizationCodeAuthenticationProvider.postProcessor()
			.postProcess(springProvider);

		assertThat(postProcessed).isInstanceOf(IssuerValidatingAuthorizationCodeAuthenticationProvider.class);
		assertThat(postProcessed.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	void doesNotWrapOtherProviders() {
		AuthenticationProvider postProcessed = IssuerValidatingAuthorizationCodeAuthenticationProvider.postProcessor()
			.postProcess(this.delegate);

		assertThat(postProcessed).isSameAs(this.delegate);
	}

	private void assertRejected(OAuth2AuthorizationCodeAuthenticationToken token) {
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.provider.authenticate(token))
			.satisfies(ex -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(INVALID_ISS_PARAMETER_ERROR_CODE);
				// Sent to the browser: no configuration details
				assertThat(ex.getError().getDescription())
					.isEqualTo("The iss parameter of the authorization response is invalid");
			});
		assertThat(this.delegate.called).isFalse();
	}

	private static OAuth2AuthorizationCodeAuthenticationToken token(boolean issParameterSupported, String query) {
		return token(ISSUER, issParameterSupported, query);
	}

	private static OAuth2AuthorizationCodeAuthenticationToken token(String issuer, boolean issParameterSupported,
			String query) {
		return token(clientRegistration(issuer, issSupported(issParameterSupported)), query);
	}

	private static OAuth2AuthorizationCodeAuthenticationToken token(ClientRegistration clientRegistration,
			String query) {
		var authorizationResponse = OAuth2AuthorizationResponse.success("code")
			.state("state")
			.redirectUri(REDIRECT_URI + query)
			.build();
		return new OAuth2AuthorizationCodeAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest(), authorizationResponse));
	}

	private static OAuth2AuthorizationRequest authorizationRequest() {
		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(ISSUER + "/authorize")
			.clientId("client-id")
			.redirectUri(REDIRECT_URI)
			.state("state")
			.build();
	}

	private static Map<String, Object> issSupported(boolean issParameterSupported) {
		return issParameterSupported
				? Map.of(IssuerValidatingAuthorizationCodeAuthenticationProvider.ISS_PARAMETER_SUPPORTED_METADATA, true)
				: Map.of();
	}

	private static ClientRegistration clientRegistration(@Nullable String issuer, Map<String, Object> metadata) {
		var builder = ClientRegistration.withRegistrationId("test")
			.clientId("client-id")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(REDIRECT_URI)
			.authorizationUri(ISSUER + "/authorize")
			.tokenUri(ISSUER + "/token")
			.providerConfigurationMetadata(new HashMap<>(metadata));
		if (issuer != null) {
			builder.issuerUri(issuer);
		}
		return builder.build();
	}

	private static final class RecordingAuthenticationProvider implements AuthenticationProvider {

		private boolean called = false;

		@Override
		public Authentication authenticate(Authentication authentication) {
			this.called = true;
			return authentication;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
		}

	}

}
