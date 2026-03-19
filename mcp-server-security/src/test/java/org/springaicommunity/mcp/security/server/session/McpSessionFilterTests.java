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

package org.springaicommunity.mcp.security.server.session;

import java.io.IOException;

import io.modelcontextprotocol.spec.HttpHeaders;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class McpSessionFilterTests {

	private final McpSessionBindingRepository sessionBindingRepository = mock(McpSessionBindingRepository.class);

	private final McpSessionFilter filter = new McpSessionFilter(this.sessionBindingRepository);

	private static final TestingAuthenticationToken USER = new TestingAuthenticationToken("user1", "password",
			AuthorityUtils.createAuthorityList("ROLE_user"));

	@BeforeEach
	void setUp() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void noSessionId() throws ServletException, IOException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilterInternal(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
		verifyNoInteractions(this.sessionBindingRepository);
	}

	@Test
	void validSessionBinding() throws ServletException, IOException, InvalidMcpSessionBindingException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		SecurityContextHolder.getContext().setAuthentication(USER);
		given(this.sessionBindingRepository.findSessionBindingId("session1")).willReturn("user1");

		this.filter.doFilterInternal(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
		verify(this.sessionBindingRepository, never()).bindSession(anyString(), anyString());
	}

	@Test
	void invalidSessionBinding403() throws ServletException, IOException, InvalidMcpSessionBindingException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		SecurityContextHolder.getContext().setAuthentication(USER);
		given(this.sessionBindingRepository.findSessionBindingId("session1")).willReturn("user2");

		this.filter.doFilterInternal(request, response, filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		assertThat(response.getErrorMessage()).isEqualTo("invalid session binding");
		verifyNoInteractions(filterChain);
		verify(this.sessionBindingRepository, never()).bindSession(anyString(), anyString());
	}

	@Test
	void responseHasSessionId() throws ServletException, IOException, InvalidMcpSessionBindingException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");
		FilterChain filterChain = mock(FilterChain.class);

		SecurityContextHolder.getContext().setAuthentication(USER);

		this.filter.doFilterInternal(request, response, filterChain);

		verify(this.sessionBindingRepository).bindSession("session1", "user1");
	}

	@Test
	void rebindExistingSession() throws InvalidMcpSessionBindingException {
		// This should never happen
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");
		FilterChain filterChain = mock(FilterChain.class);

		SecurityContextHolder.getContext().setAuthentication(USER);
		willThrow(new InvalidMcpSessionBindingException("Already bound")).given(this.sessionBindingRepository)
			.bindSession(anyString(), anyString());

		assertThatThrownBy(() -> this.filter.doFilterInternal(request, response, filterChain)).rootCause()
			.isInstanceOf(InvalidMcpSessionBindingException.class)
			.hasMessage("Already bound");
	}

	@Test
	void customSessionBindingIdResolver() throws ServletException, IOException, InvalidMcpSessionBindingException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");
		request.addHeader("X-User-Id", "custom-user");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.setSessionBindingIdResolver(req -> req.getHeader("X-User-Id"));
		given(this.sessionBindingRepository.findSessionBindingId("session1")).willReturn("custom-user");

		this.filter.doFilterInternal(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
		verify(this.sessionBindingRepository, never()).bindSession(anyString(), anyString());
	}

	@Test
	void sessionIdAndInitialize() throws InvalidMcpSessionBindingException, ServletException, IOException {
		// unspecified behavior: INITIALIZE requests with a session ID in the header
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.MCP_SESSION_ID, "session1");

		MockHttpServletResponse response = new MockHttpServletResponse();
		response.addHeader(HttpHeaders.MCP_SESSION_ID, "session2");
		FilterChain filterChain = mock(FilterChain.class);
		when(this.sessionBindingRepository.findSessionBindingId("session1")).thenReturn("user1");

		SecurityContextHolder.getContext().setAuthentication(USER);

		filter.doFilterInternal(request, response, filterChain);

		verify(this.sessionBindingRepository).findSessionBindingId("session1");
		verify(this.sessionBindingRepository).bindSession("session2", "user1");
		verify(filterChain).doFilter(request, response);
	}

}
