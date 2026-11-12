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
package org.springaicommunity.mcp.security.server.oauth2.authentication;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Entrypoint wrapping a {@link BearerTokenAuthenticationEntryPoint} and ensuring the
 * {@code resource_metadata} contains the path of the request. Should be removed after PR
 * #18542 is released.
 *
 * @see <a href=
 * "https://github.com/spring-projects/spring-security/pull/18542">spring-security/pull/18542</a>
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public final class BearerResourceMetadataTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private static final Pattern RESOURCE_METADATA_PATTERN = Pattern
		.compile("(?i)(?<=[\\s,])resource_metadata[ \\t]*=[ \\t]*\"[^\"]*\"");

	static String withResourceMetadata(String header, String url) {
		String parameter = "resource_metadata=\"" + url + "\"";

		if ("bearer".equalsIgnoreCase(header)) {
			return header + " " + parameter;
		}

		Matcher matcher = RESOURCE_METADATA_PATTERN.matcher(header);

		if (matcher.find()) {
			return matcher.replaceFirst(Matcher.quoteReplacement(parameter));
		}

		return header + ", " + parameter;
	}

	private final AuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

	private final ResourceIdentifier resourceIdentifier;

	public BearerResourceMetadataTokenAuthenticationEntryPoint(ResourceIdentifier resourceIdentifier) {
		Assert.notNull(resourceIdentifier, "resourceIdentifier cannot be null");
		this.resourceIdentifier = resourceIdentifier;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		this.delegate.commence(request, response, authException);

		String wwwAuthenticateHeader = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, withResourceMetadata(wwwAuthenticateHeader,
				buildResourceMetadataPath(request, this.resourceIdentifier)));
	}

	private String buildResourceMetadataPath(HttpServletRequest request, ResourceIdentifier resourceIdentifier) {
		return UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
			.replacePath(
					request.getContextPath() + "/.well-known/oauth-protected-resource" + resourceIdentifier.getPath())
			.replaceQuery(null)
			.fragment(null)
			.toUriString();
	}

}