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

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link McpResourceAuthorizationRequestCustomizer}.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpResourceAuthorizationRequestCustomizerTests {

	private final InMemoryMcpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final ClientRegistration registration = ClientRegistration.withRegistrationId("mcp-server")
		.clientId("client-id")
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.redirectUri("{baseUrl}/authorize/oauth2/code/{registrationId}")
		.authorizationUri("https://auth.example.com/authorize")
		.tokenUri("https://auth.example.com/token")
		.build();

	@Test
	void addsResource() {
		this.repository.save(this.registration, "https://mcp.example.com/mcp");

		var authorizationRequest = resolve();

		assertThat(authorizationRequest.getAdditionalParameters()).containsEntry("resource",
				"https://mcp.example.com/mcp");
		assertThat(queryParams(authorizationRequest).get("resource")).containsExactly("https://mcp.example.com/mcp");
	}

	@Test
	void noResourceWhenRegistrationHasNoResource() {
		this.repository.save(this.registration, null);

		var authorizationRequest = resolve();

		assertThat(authorizationRequest.getAdditionalParameters()).doesNotContainKey("resource");
		assertThat(queryParams(authorizationRequest)).doesNotContainKey("resource");
	}

	@Test
	@SuppressWarnings("NullAway") // intentionally passing null to verify it is rejected
	void requiresRepository() {
		assertThatIllegalArgumentException().isThrownBy(() -> new McpResourceAuthorizationRequestCustomizer(null))
			.withMessage("clientRegistrationRepository cannot be null");
	}

	private OAuth2AuthorizationRequest resolve() {
		var resolver = new DefaultOAuth2AuthorizationRequestResolver(this.repository,
				OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
		resolver.setAuthorizationRequestCustomizer(new McpResourceAuthorizationRequestCustomizer(this.repository));
		var request = new MockHttpServletRequest("GET", "/oauth2/authorization/mcp-server");
		request.setServletPath("/oauth2/authorization/mcp-server");
		var authorizationRequest = resolver.resolve(request);
		assertThat(authorizationRequest).isNotNull();
		return authorizationRequest;
	}

	private static MultiValueMap<String, String> queryParams(OAuth2AuthorizationRequest authorizationRequest) {
		return UriComponentsBuilder.fromUriString(authorizationRequest.getAuthorizationRequestUri())
			.build()
			.getQueryParams();
	}

}
