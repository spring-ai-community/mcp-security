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
import java.util.HashMap;
import java.util.List;

import io.modelcontextprotocol.server.transport.DefaultServerTransportSecurityValidator;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validate Origin header on MCP requests against an allowlist. Optionally validate the
 * host header value.
 *
 * <p>
 * Supports exact matches and wildcard port patterns (e.g., "https://example.com:*" for
 * origins, "example.com:*" for hosts).
 *
 * @author Daniel Garnier-Moiroux
 * @see DefaultServerTransportSecurityValidator
 */
public class OriginValidationFilter extends OncePerRequestFilter {

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

	public OriginValidationFilter(List<String> allowedOrigins, @Nullable List<String> allowedHosts) {
		var builder = new DefaultServerTransportSecurityValidator.Builder().allowedOrigins(allowedOrigins);
		if (allowedHosts != null) {
			builder.allowedHosts(allowedHosts);
		}
		this.validator = builder.build();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		var headers = new HashMap<String, List<String>>();
		var origin = request.getHeader(HttpHeaders.ORIGIN);
		if (origin != null) {
			headers.put(HttpHeaders.ORIGIN, List.of(origin));
		}
		var host = request.getHeader(HttpHeaders.HOST);
		if (host != null) {
			headers.put(HttpHeaders.HOST, List.of(host));
		}

		try {
			this.validator.validateHeaders(headers);
		}
		catch (ServerTransportSecurityException e) {
			response.setStatus(e.getStatusCode());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.getWriter().write(errorResponseTemplate.formatted(e.getMessage()));
			response.getWriter().close();
			return;
		}
		filterChain.doFilter(request, response);
	}

}
