/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.server.apikey.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ApiKeyAuthenticationFilterTests {

	private final FilterChain chain = mock(FilterChain.class);

	private final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

	private final MockHttpServletRequest request = new MockHttpServletRequest();

	private final MockHttpServletResponse response = new MockHttpServletResponse();

	private final ApiKeyEntityImpl apiKeyEntity = ApiKeyEntityImpl.builder()
		.id("api01")
		.secret("ignored")
		.name("test api key")
		.build();

	private final ApiKeyAuthenticationToken authenticated = ApiKeyAuthenticationToken.authenticated(this.apiKeyEntity,
			AuthorityUtils.NO_AUTHORITIES);

	@BeforeEach
	void setUp() {
		when(authenticationManager.authenticate(any())).thenReturn(this.authenticated);
		SecurityContextHolder.clearContext();
	}

	@Test
	void whenApiKeyPresentThenAuthenticates() throws ServletException, IOException {
		var filter = new ApiKeyAuthenticationFilter(this.authenticationManager);
		this.request.addHeader("X-API-key", "api01.secret");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(this.authenticated);
	}

	@Test
	void whenApiKeyMalformedThenUnauthorized() throws ServletException, IOException {
		var filter = new ApiKeyAuthenticationFilter(this.authenticationManager);
		this.request.addHeader("X-API-key", "malformed");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

	@Test
	void whenApiKeyMissingThenPassthrough() throws ServletException, IOException {
		var filter = new ApiKeyAuthenticationFilter(this.authenticationManager);

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	void whenCustomConverterThenUses() throws ServletException, IOException {
		var converter = new ApiKeyAuthenticationConverter("x-test-header");
		var filter = new ApiKeyAuthenticationFilter(this.authenticationManager, converter);
		this.request.addHeader("x-test-header", "api01.secret");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(this.authenticated);
	}

}
