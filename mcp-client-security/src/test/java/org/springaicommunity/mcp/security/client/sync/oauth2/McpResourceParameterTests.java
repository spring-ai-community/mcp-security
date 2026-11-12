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
import org.springaicommunity.mcp.security.client.sync.config.McpClientOAuth2Configurer;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class McpResourceParameterTests {

	private static final String RESOURCE = "https://mcp.example.com/mcp";

	private static final String CALLBACK = "https://app.example.com/callback";

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final ClientRegistration registration = ClientRegistration.withRegistrationId("test")
		.clientId("test-client")
		.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.redirectUri(CALLBACK)
		.authorizationUri("https://auth.example.com/authorize")
		.tokenUri("https://auth.example.com/token")
		.build();

	@Test
	void customAuthorizationResolverIncludesResourceAndPreservesPkce() {
		this.repository.addClientRegistration(this.registration, RESOURCE);
		var request = authorizationResolver().resolve(new MockHttpServletRequest("GET", "/oauth2/authorization/test"),
				"test");

		assertThat(request).isNotNull();
		assertThat(request.getAdditionalParameters()).containsEntry("resource", RESOURCE)
			.containsEntry(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		assertThat(request.getAuthorizationRequestUri()).contains("resource=https://mcp.example.com/mcp");
	}

	@Test
	void customTokenClientIncludesResourceWithCustomRestClient() {
		this.repository.addClientRegistration(this.registration, RESOURCE);
		var builder = RestClient.builder()
			.messageConverters(converters -> converters.add(0, new OAuth2AccessTokenResponseHttpMessageConverter()));
		var server = MockRestServiceServer.bindTo(builder).build();
		var request = authorizationResolver().resolve(new MockHttpServletRequest("GET", "/oauth2/authorization/test"),
				"test");
		assertThat(request).isNotNull();
		var parameters = new LinkedMultiValueMap<String, String>();
		parameters.add("grant_type", "authorization_code");
		parameters.add("code", "test-code");
		parameters.add("redirect_uri", CALLBACK);
		parameters.add("client_id", "test-client");
		parameters.add("code_verifier", request.getAttribute(PkceParameterNames.CODE_VERIFIER));
		parameters.add("resource", RESOURCE);
		server.expect(requestTo("https://auth.example.com/token"))
			.andExpect(method(HttpMethod.POST))
			.andExpect(content().formData(parameters))
			.andRespond(withSuccess("{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
					MediaType.APPLICATION_JSON));
		var client = new RestClientAuthorizationCodeTokenResponseClient();
		client.setRestClient(builder.build());
		client.addParametersConverter(McpClientOAuth2Configurer.mcpTokenRequestParametersConverter(this.repository));
		var state = request.getState();
		assertThat(state).isNotNull();
		var response = OAuth2AuthorizationResponse.success("test-code").redirectUri(CALLBACK).state(state).build();

		var token = client.getTokenResponse(new OAuth2AuthorizationCodeGrantRequest(this.registration,
				new OAuth2AuthorizationExchange(request, response)));

		assertThat(token.getAccessToken().getTokenValue()).isEqualTo("test-token");
		server.verify();
	}

	private DefaultOAuth2AuthorizationRequestResolver authorizationResolver() {
		var resolver = new DefaultOAuth2AuthorizationRequestResolver(this.repository, "/oauth2/authorization");
		resolver.setAuthorizationRequestCustomizer(
				McpClientOAuth2Configurer.mcpAuthorizationRequestCustomizer(this.repository));
		return resolver;
	}

}
