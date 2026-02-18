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

package org.springaicommunity.mcp.security.client.sync.oauth2.metadata;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Service to obtain metadata from an MCP server, from WWW-Authenticate headers on
 * unauthorized calls and from OAuth2 Protected Resource Metadata endpoint.
 * <p>
 * Uses a RestClient internally to perform HTTP requests. By default, uses a new rest
 * client with a Jackson JSON mapper.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9728">RFC9728 - Protected
 * Resource Metadata</a>
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#protected-resource-metadata-discovery-requirements">MCP
 * - Protected Resource Metadata Discovery Requirements</a>
 */
public class McpMetadataDiscoveryService {

	private static final Logger log = LoggerFactory.getLogger(McpMetadataDiscoveryService.class);

	private final RestClient restClient;

	public McpMetadataDiscoveryService() {
		this.restClient = RestClient.builder()
			.configureMessageConverters((converters) -> converters.registerDefaults()
				.withJsonConverter(new JacksonJsonHttpMessageConverter(JsonMapper.builder()
					.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
					.changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_NULL)))))
			.build();
	}

	public McpMetadataDiscoveryService(RestClient restClient) {
		this.restClient = restClient;
	}

	/**
	 * Get metadata from the WWW-authenticate header on an unauthorized request.
	 */
	@Nullable public WwwAuthenticateParameters getWwwAuthenticateParameters(String serverUrl) {
		log.debug("Getting www-authenticate parameter");
		try {
			log.debug("Getting WWW-authenticate header for {}", serverUrl);
			this.restClient.post().uri(serverUrl).retrieve().toBodilessEntity();
		}
		catch (HttpClientErrorException.Unauthorized unauthorized) {
			var headers = unauthorized.getResponseHeaders();
			if (headers == null) {
				return null;
			}
			var authenticateHeader = headers.getFirst("www-authenticate");
			if (authenticateHeader == null) {
				log.debug("No WWW-authenticate header");
				return null;
			}
			log.debug("Got WWW-authenticate={}", authenticateHeader);
			var protectedResourceMetadataUrl = extractWwwAuthenticateParameters("resource_metadata",
					authenticateHeader);
			if (protectedResourceMetadataUrl == null) {
				return null;
			}
			var scope = extractWwwAuthenticateParameters("scope", authenticateHeader);
			var authenticateParams = new WwwAuthenticateParameters(protectedResourceMetadataUrl, scope);
			log.debug("Got www-authenticate parameters {}", authenticateParams);
			return authenticateParams;
		}
		log.debug("Could not get www-authenticate parameters");
		return null;
	}

	/**
	 * Get full MCP Server metadata, both from the WWW-Authenticate header and from the
	 * Protected Resource Metadata document.
	 */
	public McpMetadata getMcpMetadata(String mcpServerUrl) {
		var wwwAuthenticateParameters = getWwwAuthenticateParameters(mcpServerUrl);
		var candidateUrls = new ArrayList<String>();
		if (wwwAuthenticateParameters != null) {
			candidateUrls.add(wwwAuthenticateParameters.resourceMetadata());
		}
		candidateUrls.add(computeWellKnownProtectedResourceUrl(mcpServerUrl, true));
		candidateUrls.add(computeWellKnownProtectedResourceUrl(mcpServerUrl, false));
		var protectedResourceMetadata = getProtectedResourceMetadata(candidateUrls);
		if (!mcpServerUrl.startsWith(protectedResourceMetadata.resource())) {
			throw new IllegalStateException("Resource identifier [%s] does not match MCP Server url [%s]"
				.formatted(protectedResourceMetadata.resource(), mcpServerUrl));
		}
		return new McpMetadata(wwwAuthenticateParameters, protectedResourceMetadata);
	}

	/**
	 * Get Protected Resource Metadata document.
	 * @param resourceMetadataUrlCandidates The URLs from which to fetch the document
	 * @return The Protected Resource Metadata document
	 */
	public ProtectedResourceMetadata getProtectedResourceMetadata(Collection<String> resourceMetadataUrlCandidates) {
		for (var protectedResourceMetadataUrl : resourceMetadataUrlCandidates) {
			try {
				log.debug("Reading protected resource metadata [{}]", protectedResourceMetadataUrl);
				var prm = restClient.get()
					.uri(protectedResourceMetadataUrl)
					.retrieve()
					.body(ProtectedResourceMetadata.class);
				if (prm == null) {
					continue;
				}
				log.debug("Got Protected Resource Metadata: {}", prm);
				return prm;
			}
			catch (HttpClientErrorException.NotFound | HttpClientErrorException.Unauthorized ignored) {
				// ignored
			}
		}
		throw new IllegalStateException("Could not find protected resource metadata");
	}

	private String computeWellKnownProtectedResourceUrl(String mcpServerUrl, boolean includePath) {
		var path = "";
		if (includePath) {
			var url = UriComponentsBuilder.fromUriString(mcpServerUrl).build();
			if (url.getPath() != null) {
				path = url.getPath();
			}
		}
		var prmUrl = UriComponentsBuilder.fromUriString(mcpServerUrl)
			.replacePath("/.well-known/oauth-protected-resource" + path)
			.toUriString();
		return prmUrl;
	}

	@Nullable private static String extractWwwAuthenticateParameters(String parameterName, String authenticateHeader) {
		var pattern = Pattern.compile(parameterName + "=(?:\"([^\"]+)\"|([^\\s,]+))");
		var matcher = pattern.matcher(authenticateHeader);
		if (matcher.find()) {
			return matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
		}
		return null;
	}

}
