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

import java.util.Collection;

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

	private static final String WELL_KNOWN_PATH_SEGMENT = "/.well-known/oauth-protected-resource";

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
	public @Nullable WwwAuthenticateParameters getWwwAuthenticateParameters(String serverUrl) {
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
			var authenticateParameters = WwwAuthenticateParameters.parse(authenticateHeader);
			log.debug("Got www-authenticate parameters {}", authenticateParameters);
			return authenticateParameters;
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
		return getMcpMetadata(mcpServerUrl, wwwAuthenticateParameters);
	}

	public McpMetadata getMcpMetadata(String mcpServerUrl,
			@Nullable WwwAuthenticateParameters wwwAuthenticateParameters) {
		ProtectedResourceMetadata metadata = null;
		if (wwwAuthenticateParameters != null) {
			metadata = getProtectedResourceMetadata(wwwAuthenticateParameters.getResourceMetadata());
			if (metadata != null && !metadata.resource().equals(mcpServerUrl)) {
				throw new IllegalStateException("Resource identifier [%s] does not match MCP Server url [%s]"
					.formatted(metadata.resource(), mcpServerUrl));
			}
		}
		var rootUrl = UriComponentsBuilder.fromUriString(mcpServerUrl).replacePath(null).toUriString();
		var path = UriComponentsBuilder.fromUriString(mcpServerUrl).build().getPath();
		if (metadata == null) {
			var candidateUrl = computeWellKnownProtectedResourceUrl(rootUrl, path);
			metadata = getProtectedResourceMetadata(candidateUrl);
			if (metadata != null && !metadata.resource().equals(mcpServerUrl)) {
				throw new IllegalStateException("Resource identifier [%s] does not match MCP Server url [%s]"
					.formatted(metadata.resource(), mcpServerUrl));
			}
		}
		if (metadata == null) {
			var candidateUrl = computeWellKnownProtectedResourceUrl(rootUrl, null);
			metadata = getProtectedResourceMetadata(candidateUrl);
			if (metadata != null && !metadata.resource().equals(rootUrl)) {
				throw new IllegalStateException("Resource identifier [%s] does not match MCP Server root url [%s]"
					.formatted(metadata.resource(), mcpServerUrl));
			}
		}
		if (metadata == null) {
			throw new IllegalStateException("Could not find protected resource metadata");
		}
		return new McpMetadata(wwwAuthenticateParameters, metadata);
	}

	/**
	 * Get Protected Resource Metadata document.
	 * @param mcpServerUrl The URL of the MCP server, used for validation
	 * @param resourceMetadataUrlCandidates The URLs from which to fetch the document
	 * @return The Protected Resource Metadata document
	 */
	public ProtectedResourceMetadata getProtectedResourceMetadata(String mcpServerUrl,
			Collection<String> resourceMetadataUrlCandidates) {
		for (var protectedResourceMetadataUrl : resourceMetadataUrlCandidates) {
			var prm = getProtectedResourceMetadata(protectedResourceMetadataUrl);
			if (prm != null) {
				if (mcpServerUrl.startsWith(prm.resource())) {
					return prm;
				}
				log.debug("Resource identifier [{}] does not match MCP Server url [{}]", prm.resource(), mcpServerUrl);
			}
		}
		throw new IllegalStateException("Could not find protected resource metadata");
	}

	/**
	 * Get Protected Resource Metadata document.
	 * @param resourceMetadataUrl The URL from which to fetch the document
	 * @return The Protected Resource Metadata document
	 */
	public @Nullable ProtectedResourceMetadata getProtectedResourceMetadata(String resourceMetadataUrl) {
		try {
			log.debug("Reading protected resource metadata [{}]", resourceMetadataUrl);
			var prm = restClient.get().uri(resourceMetadataUrl).retrieve().body(ProtectedResourceMetadata.class);
			if (prm == null) {
				log.debug("Protected resource metadata body is null for [{}]", resourceMetadataUrl);
				return null;
			}
			log.debug("Got Protected Resource Metadata: {}", prm);
			return prm;
		}
		catch (HttpClientErrorException.NotFound | HttpClientErrorException.Unauthorized e) {
			log.debug("Could not get protected resource metadata from [{}]: {}", resourceMetadataUrl, e.getMessage());
		}
		return null;
	}

	private String computeWellKnownProtectedResourceUrl(String rootUrl, @Nullable String path) {
		path = path != null ? path : "";
		return UriComponentsBuilder.fromUriString(rootUrl)
			.replacePath(null)
			.replacePath(WELL_KNOWN_PATH_SEGMENT + path)
			.toUriString();
	}

}
