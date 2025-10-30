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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/**
 * @author Daniel Garnier-Moiroux
 */
public class ApiKeyAuthenticationFilter extends AuthenticationFilter {

	public static final String DEFAULT_API_KEY_HEADER = "X-API-Key";

	public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager, new ApiKeyAuthenticationConverter(DEFAULT_API_KEY_HEADER));

		setSuccessHandler(new PassthroughSuccessHandler());
		setFailureHandler(
				new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
	}

	public void setApiKeyHeader(String apiKeyHeader) {
		setAuthenticationConverter(new ApiKeyAuthenticationConverter(apiKeyHeader));
	}

	private static class PassthroughSuccessHandler implements AuthenticationSuccessHandler {

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
				Authentication authentication) throws IOException, ServletException {
			chain.doFilter(request, response);
		}

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication authentication) throws IOException, ServletException {
			throw new RuntimeException("Should never reach this");
		}

	}

}