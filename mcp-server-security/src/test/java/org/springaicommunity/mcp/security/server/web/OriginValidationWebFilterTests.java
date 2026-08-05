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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.json.JsonContent;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Daniel Garnier-Moiroux
 */
class OriginValidationWebFilterTests {

	private static String JSONRPC_ERROR = """
			{
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32000
			    },
			    "id": null
			}""";

	private final WebFilterChain chain = mock(WebFilterChain.class);

	OriginValidationWebFilterTests() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
	}

	@Test
	void whenOriginHeaderMissingThenPassesThrough() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), null);
		var exchange = exchange(null, null);

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenOriginAllowedThenPassesThrough() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), null);
		var exchange = exchange("https://allowed.example.com", null);

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenOriginMatchesWildcardPortThenPassesThrough() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com:*"), null);
		var exchange = exchange("https://allowed.example.com:8443", null);

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenOriginNotAllowedThenForbidden() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), null);
		var exchange = exchange("https://evil.example.com", null);

		filter.filter(exchange, this.chain).block();

		verifyNoInteractions(this.chain);
		assertThat(statusCode(exchange)).isEqualTo(403);
		assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
		new JsonContent(body(exchange)).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Origin header");
	}

	@Test
	void whenAllowedOriginsEmptyThenOriginIsRejected() {
		var filter = new OriginValidationWebFilter(List.of(), null);
		var exchange = exchange("https://allowed.example.com", null);

		filter.filter(exchange, this.chain).block();

		verifyNoInteractions(this.chain);
		assertThat(statusCode(exchange)).isEqualTo(403);
	}

	@Test
	void whenAllowedHostsNotConfiguredThenHostHeaderIsIgnored() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), null);
		var exchange = exchange("https://allowed.example.com", "unrelated.example");

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenHostAllowedThenPassesThrough() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		var exchange = exchange("https://allowed.example.com", "allowed.example");

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenHostMatchesWildcardPortThenPassesThrough() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"),
				List.of("allowed.example:*"));
		var exchange = exchange("https://allowed.example.com", "allowed.example:8080");

		filter.filter(exchange, this.chain).block();

		verify(this.chain).filter(exchange);
	}

	@Test
	void whenHostNotAllowedThenMisdirected() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		var exchange = exchange("https://allowed.example.com", "evil.example");

		filter.filter(exchange, this.chain).block();

		verifyNoInteractions(this.chain);
		assertThat(statusCode(exchange)).isEqualTo(421);
		assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
		new JsonContent(body(exchange)).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

	@Test
	void whenHostRequiredButMissingThenMisdirected() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		var exchange = exchange("https://allowed.example.com", null);

		filter.filter(exchange, this.chain).block();

		verifyNoInteractions(this.chain);
		assertThat(statusCode(exchange)).isEqualTo(421);
		assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
		new JsonContent(body(exchange)).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

	@Test
	void whenAllowedHostsConfiguredButOriginHeaderMissingThenHostIsChecked() {
		var filter = new OriginValidationWebFilter(List.of("https://allowed.example.com"), List.of("allowed.example"));
		var exchange = exchange(null, "evil.example");

		filter.filter(exchange, this.chain).block();

		verifyNoInteractions(this.chain);
		assertThat(statusCode(exchange)).isEqualTo(421);
		assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
		new JsonContent(body(exchange)).assertThat()
			.isLenientlyEqualTo(JSONRPC_ERROR)
			.extractingPath("$.error.message")
			.isEqualTo("Invalid Host header");
	}

	private static MockServerWebExchange exchange(@Nullable String origin, @Nullable String host) {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/mcp");
		if (origin != null) {
			request = request.header(HttpHeaders.ORIGIN, origin);
		}
		if (host != null) {
			request = request.header(HttpHeaders.HOST, host);
		}
		return MockServerWebExchange.from(request.build());
	}

	private static int statusCode(MockServerWebExchange exchange) {
		var status = exchange.getResponse().getStatusCode();
		assertThat(status).isNotNull();
		return status.value();
	}

	private static String body(MockServerWebExchange exchange) {
		return Objects.requireNonNull(exchange.getResponse().getBodyAsString().block());
	}

}
