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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import io.modelcontextprotocol.client.transport.customizer.McpAsyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("deprecation")
class OAuth2AsyncHttpRequestCustomizerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String TOKEN_VALUE = "test-access-token";

	private static final URI ENDPOINT = URI.create("https://mcp.example.com");

	private static final Duration TIMEOUT = Duration.ofSeconds(5);

	private final Authentication authentication = new TestingAuthenticationToken("user", "password");

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final AuthorizedClientServiceOAuth2AuthorizedClientManager serviceAuthorizedClientManager = mock(
			AuthorizedClientServiceOAuth2AuthorizedClientManager.class);

	private final ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);

	private final ServletRequestAttributes requestAttributes = new ServletRequestAttributes(
			mock(HttpServletRequest.class), mock(HttpServletResponse.class));

	private final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(ENDPOINT);

	@ParameterizedTest
	@EnumSource(GrantFlow.class)
	void defersAndOffloadsAuthorizationWhilePreservingRequestContext(GrantFlow flow) {
		var subscriptionThread = new AtomicReference<Thread>();
		var registration = clientRegistration();
		given(this.clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willAnswer(invocation -> {
			assertBlockingAllowed(subscriptionThread.get());
			return registration;
		});
		var manager = manager(flow);
		given(manager.authorize(any(OAuth2AuthorizeRequest.class))).willAnswer(invocation -> {
			assertBlockingAllowed(subscriptionThread.get());
			return authorizedClient(registration);
		});

		var result = Mono.from(customizer(flow).customize(this.requestBuilder, "POST", ENDPOINT, "{}", context(flow)));

		verifyNoInteractions(this.clientRegistrationRepository, this.authorizedClientManager,
				this.serviceAuthorizedClientManager);
		assertThat(this.requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION)).isEmpty();

		var customizedBuilder = Mono.defer(() -> {
			assertThat(Schedulers.isInNonBlockingThread()).isTrue();
			subscriptionThread.set(Thread.currentThread());
			return result;
		}).subscribeOn(Schedulers.parallel()).block(TIMEOUT);

		assertThat(customizedBuilder).isSameAs(this.requestBuilder);
		assertThat(this.requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
			.hasValue("Bearer " + TOKEN_VALUE);
		var authorizeRequestCaptor = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		verify(manager).authorize(authorizeRequestCaptor.capture());
		var authorizeRequest = authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
		if (flow.hasUserContext()) {
			assertThat(authorizeRequest.getPrincipal()).isSameAs(this.authentication);
			assertThat(authorizeRequest.getAttributes())
				.containsEntry(HttpServletRequest.class.getName(), this.requestAttributes.getRequest())
				.containsEntry(HttpServletResponse.class.getName(), this.requestAttributes.getResponse());
			verifyNoInteractions(this.serviceAuthorizedClientManager);
		}
		else {
			assertThat(authorizeRequest.getPrincipal().getName()).isEqualTo("mcp-client-service");
			assertThat(authorizeRequest.getAttributes()).isEmpty();
			verifyNoInteractions(this.authorizedClientManager);
		}
		if (flow == GrantFlow.AUTHORIZATION_CODE) {
			verify(this.clientRegistrationRepository).findByRegistrationId(REGISTRATION_ID);
		}
		else {
			verifyNoInteractions(this.clientRegistrationRepository);
		}
	}

	@ParameterizedTest
	@EnumSource(GrantFlow.class)
	void propagatesAuthorizationFailureOnSubscription(GrantFlow flow) {
		var failure = new ClientAuthorizationRequiredException(REGISTRATION_ID);
		given(this.clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(clientRegistration());
		given(manager(flow).authorize(any(OAuth2AuthorizeRequest.class))).willThrow(failure);

		var result = Mono.from(customizer(flow).customize(this.requestBuilder, "POST", ENDPOINT, "{}", context(flow)));

		verifyNoInteractions(this.clientRegistrationRepository, this.authorizedClientManager,
				this.serviceAuthorizedClientManager);
		assertThatThrownBy(() -> result.block(TIMEOUT)).isSameAs(failure);
		assertThat(this.requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION)).isEmpty();
	}

	@ParameterizedTest
	@EnumSource(MissingContext.class)
	void authorizationCodeSkipsAuthorizationWhenUserContextIsMissing(MissingContext missingContext) {
		var context = switch (missingContext) {
			case BOTH -> McpTransportContext.EMPTY;
			case AUTHENTICATION -> McpTransportContext.create(
					Map.of(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, this.requestAttributes));
			case REQUEST_ATTRIBUTES -> McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, this.authentication));
		};

		var result = Mono
			.from(authorizationCodeCustomizer().asAsync()
				.customize(this.requestBuilder, "POST", ENDPOINT, "{}", context))
			.block(TIMEOUT);

		assertThat(result).isSameAs(this.requestBuilder);
		assertThat(this.requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION)).isEmpty();
		verifyNoInteractions(this.clientRegistrationRepository, this.authorizedClientManager,
				this.serviceAuthorizedClientManager);
	}

	@Test
	void authorizationCodeSkipsMissingRegistrationToAllowDynamicRegistration() {
		var result = Mono.from(authorizationCodeCustomizer().asAsync()
			.customize(this.requestBuilder, "POST", ENDPOINT, "{}", context(GrantFlow.AUTHORIZATION_CODE)));

		verifyNoInteractions(this.clientRegistrationRepository);
		assertThat(result.block(TIMEOUT)).isSameAs(this.requestBuilder);
		verify(this.clientRegistrationRepository).findByRegistrationId(REGISTRATION_ID);
		verifyNoInteractions(this.authorizedClientManager);
		assertThat(this.requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION)).isEmpty();
	}

	@Test
	void authorizationCodeHonorsFailOnMissingRegistration() {
		var customizer = authorizationCodeCustomizer();
		customizer.failOnMissingClientRegistration(true);

		var result = Mono.from(customizer.asAsync()
			.customize(this.requestBuilder, "POST", ENDPOINT, "{}", context(GrantFlow.AUTHORIZATION_CODE)));

		verifyNoInteractions(this.clientRegistrationRepository);
		assertThatThrownBy(() -> result.block(TIMEOUT)).isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining(REGISTRATION_ID);
		verifyNoInteractions(this.authorizedClientManager);
	}

	private McpAsyncHttpClientRequestCustomizer customizer(GrantFlow flow) {
		return switch (flow) {
			case AUTHORIZATION_CODE -> authorizationCodeCustomizer().asAsync();
			case CLIENT_CREDENTIALS ->
				new OAuth2ClientCredentialsSyncHttpRequestCustomizer(this.serviceAuthorizedClientManager,
						REGISTRATION_ID)
					.asAsync();
			case HYBRID_AUTHORIZATION_CODE, HYBRID_CLIENT_CREDENTIALS ->
				new OAuth2HybridSyncHttpRequestCustomizer(this.authorizedClientManager,
						this.serviceAuthorizedClientManager, REGISTRATION_ID, REGISTRATION_ID)
					.asAsync();
		};
	}

	private OAuth2AuthorizationCodeSyncHttpRequestCustomizer authorizationCodeCustomizer() {
		return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, REGISTRATION_ID);
	}

	private OAuth2AuthorizedClientManager manager(GrantFlow flow) {
		return flow.hasUserContext() ? this.authorizedClientManager : this.serviceAuthorizedClientManager;
	}

	private McpTransportContext context(GrantFlow flow) {
		return flow.hasUserContext()
				? McpTransportContext
					.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, this.authentication,
							AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, this.requestAttributes))
				: McpTransportContext.EMPTY;
	}

	private static void assertBlockingAllowed(@Nullable Thread subscriptionThread) {
		assertThat(subscriptionThread).isNotNull();
		assertThat(Thread.currentThread()).isNotSameAs(subscriptionThread);
		assertThat(Schedulers.isInNonBlockingThread()).isFalse();
	}

	private static ClientRegistration clientRegistration() {
		return ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientId("test-client-id")
			.redirectUri("https://example.com/callback")
			.authorizationUri("https://auth.example.com/authorize")
			.tokenUri("https://auth.example.com/token")
			.build();
	}

	private static OAuth2AuthorizedClient authorizedClient(ClientRegistration registration) {
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN_VALUE, Instant.now(),
				Instant.now().plusSeconds(300), Set.of());
		return new OAuth2AuthorizedClient(registration, "user", accessToken);
	}

	private enum GrantFlow {

		AUTHORIZATION_CODE, CLIENT_CREDENTIALS, HYBRID_AUTHORIZATION_CODE, HYBRID_CLIENT_CREDENTIALS;

		boolean hasUserContext() {
			return this == AUTHORIZATION_CODE || this == HYBRID_AUTHORIZATION_CODE;
		}

	}

	private enum MissingContext {

		BOTH, AUTHENTICATION, REQUEST_ATTRIBUTES

	}

}
