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
package org.springaicommunity.mcp.security.resourceserver.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 */
public final class BearerResourceMetadataTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final AuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

	private final String protectedResourceMetadataEndpointUri;

	public BearerResourceMetadataTokenAuthenticationEntryPoint(String protectedResourceMetadataEndpointUri) {
		Assert.hasText(protectedResourceMetadataEndpointUri, "protectedResourceMetadataEndpointUri cannot be empty");
		this.protectedResourceMetadataEndpointUri = protectedResourceMetadataEndpointUri;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		this.delegate.commence(request, response, authException);

		String wwwAuthenticateHeader = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
		if ("bearer".equalsIgnoreCase(wwwAuthenticateHeader)) {
			wwwAuthenticateHeader += " ";
		}
		else {
			wwwAuthenticateHeader += ", ";
		}
		wwwAuthenticateHeader += "resource_metadata=" + this.protectedResourceMetadataEndpointUri;

		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
	}

}