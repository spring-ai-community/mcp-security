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

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

import io.modelcontextprotocol.server.transport.DefaultServerTransportSecurityValidator;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Validate Origin header on MCP requests against an allowlist. Optionally validate the
 * host header value. Reactive counterpart of {@link OriginValidationFilter}.
 *
 * <p>
 * Supports exact matches and wildcard port patterns (e.g., "https://example.com:*" for
 * origins, "example.com:*" for hosts).
 *
 * @author Daniel Garnier-Moiroux
 * @see DefaultServerTransportSecurityValidator
 */
public class OriginValidationWebFilter implements WebFilter {

	private final DefaultServerTransportSecurityValidator validator;

	private static final String errorResponseTemplate = """
			{
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32000,
			        "message": "%s"
			    },
			    "id": null
			}""";

	public OriginValidationWebFilter(List<String> allowedOrigins, @Nullable List<String> allowedHosts) {
		var builder = new DefaultServerTransportSecurityValidator.Builder().allowedOrigins(allowedOrigins);
		if (allowedHosts != null) {
			builder.allowedHosts(allowedHosts);
		}
		this.validator = builder.build();
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		var requestHeaders = exchange.getRequest().getHeaders();
		var headers = new HashMap<String, List<String>>();
		var origin = requestHeaders.getFirst(HttpHeaders.ORIGIN);
		if (origin != null) {
			headers.put(HttpHeaders.ORIGIN, List.of(origin));
		}
		var host = requestHeaders.getFirst(HttpHeaders.HOST);
		if (host != null) {
			headers.put(HttpHeaders.HOST, List.of(host));
		}

		try {
			this.validator.validateHeaders(headers);
		}
		catch (ServerTransportSecurityException e) {
			return writeError(exchange, e);
		}
		return chain.filter(exchange);
	}

	private static Mono<Void> writeError(ServerWebExchange exchange, ServerTransportSecurityException exception) {
		var response = exchange.getResponse();
		response.setStatusCode(HttpStatusCode.valueOf(exception.getStatusCode()));
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		var body = errorResponseTemplate.formatted(exception.getMessage()).getBytes(StandardCharsets.UTF_8);
		return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
	}

}
