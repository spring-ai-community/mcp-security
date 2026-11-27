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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.JsonRpc.JSONRPCRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestHeaders;
import io.modelcontextprotocol.modern.client.transport.McpTransportRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common.OAuth2AuthorizationCodeAccessTokenResolver;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestCustomizer}. The token logic is tested
 * in {@code OAuth2AuthorizationCodeAccessTokenResolverTests}.
 *
 * @author Daniel Garnier-Moiroux
 */
class OAuth2AuthorizationCodeRequestCustomizerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final McpTransportContext CONTEXT = McpTransportContext.create(Map.of("test", "context"));

	private static final McpTransportRequest TRANSPORT_REQUEST = McpTransportRequest
		.builder(new JSONRPCRequest("tools/list", 1), "2026-07-28")
		.build();

	private static final McpHttpRequest REQUEST = McpHttpRequest
		.builder(URI.create("https://mcp.example.com"), TRANSPORT_REQUEST, "{}")
		.build();

	private final OAuth2AuthorizationCodeAccessTokenResolver accessTokenResolver = mock(
			OAuth2AuthorizationCodeAccessTokenResolver.class);

	private final McpHttpRequestHeaders headers = McpHttpRequestHeaders.forRequest(TRANSPORT_REQUEST);

	private OAuth2AuthorizationCodeRequestCustomizer customizer;

	@BeforeEach
	void setUp() {
		this.customizer = new OAuth2AuthorizationCodeRequestCustomizer(mock(OAuth2AuthorizedClientManager.class),
				mock(ClientRegistrationRepository.class), REGISTRATION_ID);
		ReflectionTestUtils.setField(this.customizer, "accessTokenResolver", this.accessTokenResolver);
	}

	@Test
	void addsBearerToken() {
		when(this.accessTokenResolver.resolve(CONTEXT)).thenReturn(accessToken());

		this.customizer.customize(REQUEST, this.headers, CONTEXT);

		assertThat(this.headers.get(HttpHeaders.AUTHORIZATION)).containsExactly("Bearer test-access-token");
	}

	@Test
	void noToken() {
		when(this.accessTokenResolver.resolve(CONTEXT)).thenReturn(null);

		this.customizer.customize(REQUEST, this.headers, CONTEXT);

		assertThat(this.headers.get(HttpHeaders.AUTHORIZATION)).isEmpty();
	}

	@Test
	void authorizationRequired() {
		when(this.accessTokenResolver.resolve(CONTEXT))
			.thenThrow(new ClientAuthorizationRequiredException(REGISTRATION_ID));

		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> this.customizer.customize(REQUEST, this.headers, CONTEXT));
		assertThat(this.headers.get(HttpHeaders.AUTHORIZATION)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(booleans = { true, false })
	void failOnMissingClientRegistration(boolean failOnMissingClientRegistration) {
		this.customizer.setFailOnMissingClientRegistration(failOnMissingClientRegistration);

		verify(this.accessTokenResolver).setFailOnMissingClientRegistration(failOnMissingClientRegistration);
	}

	private static OAuth2AccessToken accessToken() {
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "test-access-token", Instant.now(),
				Instant.now().plusSeconds(300));
	}

}
