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

package org.springaicommunity.mcp.security.server.web;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.json.JsonContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Daniel Garnier-Moiroux
 */
class OriginValidationFilterTests {

	private static String JSONRPC_ERROR = """
			{
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32000
			    },
			    "id": null
			}""";

	private final FilterChain chain = mock(FilterChain.class);

	private final MockHttpServletRequest request = new MockHttpServletRequest();

	private final MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	void whenOriginHeaderMissingThenPassesThrough() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), null);

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenOriginAllowedThenPassesThrough() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), null);
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenOriginMatchesWildcardPortThenPassesThrough() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com:*"), null);
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com:8443");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenOriginNotAllowedThenForbidden() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), null);
		this.request.addHeader(HttpHeaders.ORIGIN, "https://evil.example.com");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(403);
		assertThat(this.response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContent(this.response.getContentAsString()).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Origin header");
	}

	@Test
	void whenAllowedOriginsEmptyThenOriginIsRejected() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of(), null);
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(403);
	}

	@Test
	void whenAllowedHostsNotConfiguredThenHostHeaderIsIgnored() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), null);
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");
		this.request.addHeader(HttpHeaders.HOST, "unrelated.example");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenHostAllowedThenPassesThrough() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");
		this.request.addHeader(HttpHeaders.HOST, "allowed.example");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenHostMatchesWildcardPortThenPassesThrough() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), List.of("allowed.example:*"));
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");
		this.request.addHeader(HttpHeaders.HOST, "allowed.example:8080");

		filter.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	void whenHostNotAllowedThenMisdirected() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");
		this.request.addHeader(HttpHeaders.HOST, "evil.example");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(421);
		assertThat(this.response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContent(this.response.getContentAsString()).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

	@Test
	void whenHostRequiredButMissingThenMisdirected() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		this.request.addHeader(HttpHeaders.ORIGIN, "https://allowed.example.com");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(421);
		assertThat(this.response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContent(this.response.getContentAsString()).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

	@Test
	void whenAllowedHostsConfiguredButOriginHeaderMissingThenHostIsChecked() throws ServletException, IOException {
		var filter = new OriginValidationFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		this.request.addHeader(HttpHeaders.HOST, "evil.example");

		filter.doFilter(this.request, this.response, this.chain);

		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(421);
		assertThat(this.response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		new JsonContent(this.response.getContentAsString()).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

}
