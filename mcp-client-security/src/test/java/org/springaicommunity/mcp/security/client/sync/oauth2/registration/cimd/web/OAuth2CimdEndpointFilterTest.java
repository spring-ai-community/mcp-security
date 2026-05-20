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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.web;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.json.JsonContent;
import org.springframework.test.json.JsonContentAssert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2CimdEndpointFilterTest {

	private final OAuth2CimdEndpointFilter filter = new OAuth2CimdEndpointFilter();

	@Test
	void requestDoesNotMatch() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/other-path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		this.filter.doFilter(request, response, filterChain);

		assertThat(response.getContentAsByteArray()).isEmpty();
		assertThat(filterChain.getRequest()).isSameAs(request);
		assertThat(filterChain.getResponse()).isSameAs(response);
	}

	@Test
	void matchesHttps() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/my-client/client-id-metadata.json");
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setContextPath("");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		this.filter.doFilter(request, response, filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContentAssert(new JsonContent(response.getContentAsString())).isLenientlyEqualTo("""
				{
					"token_endpoint_auth_method": "none",
					"grant_types": ["authorization_code","refresh_token"],
					"response_types": ["code"],
					"client_id": "https://example.com/my-client/client-id-metadata.json",
					"redirect_uris": ["https://example.com/authorize/oauth2/code/my-client"],
					"client_name": "Spring client for my-client"
				}
				""");

		assertThat(filterChain.getRequest()).isNull();
		assertThat(filterChain.getResponse()).isNull();
	}

	@Test
	void baseUrl() throws Exception {
		this.filter.setBaseUrl("https://custom-domain.com/app");

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/my-client/client-id-metadata.json");
		request.setScheme("http");
		request.setServerName("localhost");
		request.setServerPort(8080);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		this.filter.doFilter(request, response, filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContentAssert(new JsonContent(response.getContentAsString())).isLenientlyEqualTo("""
				{
					"token_endpoint_auth_method": "none",
					"grant_types": ["authorization_code","refresh_token"],
					"response_types": ["code"],
					"client_id": "https://custom-domain.com/app/my-client/client-id-metadata.json",
					"redirect_uris": ["https://custom-domain.com/app/authorize/oauth2/code/my-client"],
					"client_name": "Spring client for my-client"
				}
				""");
	}

	@Test
	void customizer() throws Exception {
		this.filter.setMetadataCustomizer((metadata) -> {
			metadata.put("custom_field", "custom_value");
			metadata.put("client_name", "Overridden Client Name");
		});

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/my-client/client-id-metadata.json");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		this.filter.doFilter(request, response, filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContentAssert(new JsonContent(response.getContentAsString())).isLenientlyEqualTo("""
				{
					"custom_field": "custom_value",
					"client_name": "Overridden Client Name"
				}
				""");
	}

	@Test
	void customMatcher() throws Exception {
		RequestMatcher customMatcher = mock(RequestMatcher.class);
		RequestMatcher.MatchResult matchResult = RequestMatcher.MatchResult
			.match(Map.of("registrationId", "custom-client"));
		given(customMatcher.matches(any(HttpServletRequest.class))).willReturn(true);
		given(customMatcher.matcher(any(HttpServletRequest.class))).willReturn(matchResult);

		this.filter.setRequestMatcher(customMatcher);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/custom-path");
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		this.filter.doFilter(request, response, filterChain);

		new JsonContentAssert(new JsonContent(response.getContentAsString())).isLenientlyEqualTo("""
				{
					"client_id": "https://example.com/custom-client/client-id-metadata.json"
				}
				""");
		verify(customMatcher).matches(request);
		verify(customMatcher).matcher(request);
	}

}
