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

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.Nullable;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Builds a {@link ClientRegistration.Builder} from an authorization server's metadata,
 * discovered in the order the MCP specification requires: RFC 8414 first, then OpenID
 * Connect Discovery. Spring Security's
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrations#fromIssuerLocation(String)}
 * reads OpenID Connect Discovery first, so it reads the wrong document when the two
 * differ.
 *
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-server-metadata-discovery">MCP
 * - Authorization Server Metadata Discovery</a>
 */
public final class McpClientRegistrations {

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<>() {
	};

	private static final RestClient defaultRestClient = RestClient.create();

	private McpClientRegistrations() {
	}

	/**
	 * Discover the authorization server metadata of {@code issuer}, trying in order:
	 * <ol>
	 * <li>{@code host/.well-known/oauth-authorization-server/path} (RFC 8414)</li>
	 * <li>{@code host/.well-known/openid-configuration/path} (RFC 8414 applied to OpenID
	 * Connect)</li>
	 * <li>{@code issuer/.well-known/openid-configuration} (OpenID Connect Discovery
	 * 1.0)</li>
	 * </ol>
	 * The first document that answers 2xx, parses and names {@code issuer} wins; a 4xx,
	 * an invalid document or another issuer moves on to the next location.
	 * @param issuer the authorization server's issuer
	 * @return a builder with the provider details set; the caller sets the client details
	 * @throws IllegalArgumentException when no location yields a valid document
	 */
	public static ClientRegistration.Builder fromIssuerLocation(String issuer) {
		return fromIssuerLocation(issuer, defaultRestClient);
	}

	/**
	 * Same as {@link #fromIssuerLocation(String)}, with the given {@link RestClient}.
	 * @param issuer the authorization server's issuer
	 * @param restClient the client for the metadata requests
	 * @return a builder with the provider details set; the caller sets the client details
	 */
	public static ClientRegistration.Builder fromIssuerLocation(String issuer, RestClient restClient) {
		Assert.hasText(issuer, "issuer cannot be empty");
		var uri = UriComponentsBuilder.fromUriString(issuer).build();
		var path = (uri.getPath() != null) ? uri.getPath() : "";
		var locations = new LinkedHashMap<String, Boolean>();
		// value: true when the location is an OpenID Connect document. Without a path the
		// last two locations are equal, so the map keeps one
		locations.put(withPath(uri, OAUTH_METADATA_PATH + path), false);
		locations.put(withPath(uri, OIDC_METADATA_PATH + path), true);
		locations.put(withPath(uri, path + OIDC_METADATA_PATH), true);

		List<String> errors = new ArrayList<>();
		for (var location : locations.entrySet()) {
			try {
				return fetch(issuer, location.getKey(), location.getValue(), restClient);
			}
			catch (HttpClientErrorException | IllegalArgumentException | IllegalStateException ex) {
				errors.add(location.getKey() + ": " + ex.getMessage());
			}
		}
		throw new IllegalArgumentException(
				"Unable to resolve the authorization server metadata of issuer \"%s\", errors: %s".formatted(issuer,
						errors));
	}

	private static String withPath(UriComponents uri, String path) {
		return UriComponentsBuilder.newInstance().uriComponents(uri).replacePath(path).build().toUriString();
	}

	private static ClientRegistration.Builder fetch(String issuer, String location, boolean oidc,
			RestClient restClient) {
		Map<String, Object> configuration = restClient.get().uri(location).retrieve().body(typeReference);
		Assert.notNull(configuration, "Authorization server metadata cannot be null");
		var json = new JSONObject(configuration);
		try {
			if (oidc) {
				var metadata = OIDCProviderMetadata.parse(json);
				var builder = withProviderConfiguration(metadata, issuer, configuration)
					.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
				if (metadata.getUserInfoEndpointURI() != null) {
					builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
				}
				return builder;
			}
			var metadata = AuthorizationServerMetadata.parse(json);
			var builder = withProviderConfiguration(metadata, issuer, configuration);
			if (metadata.getJWKSetURI() != null) {
				builder.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
			}
			if (configuration.get("userinfo_endpoint") instanceof String userInfoEndpoint) {
				builder.userInfoUri(userInfoEndpoint);
			}
			return builder;
		}
		catch (ParseException ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private static ClientRegistration.Builder withProviderConfiguration(AuthorizationServerMetadata metadata,
			String issuer, Map<String, Object> configuration) {
		var metadataIssuer = metadata.getIssuer().getValue();
		Assert.state(issuer.equals(metadataIssuer),
				() -> "The issuer \"%s\" in the metadata does not match \"%s\"".formatted(metadataIssuer, issuer));
		var builder = ClientRegistration.withRegistrationId(URI.create(issuer).getHost())
			.userNameAttributeName(IdTokenClaimNames.SUB)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientAuthenticationMethod(getClientAuthenticationMethod(metadata.getTokenEndpointAuthMethods()))
			.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.providerConfigurationMetadata(new LinkedHashMap<>(configuration))
			.issuerUri(issuer)
			.clientName(issuer);
		if (metadata.getAuthorizationEndpointURI() != null) {
			builder.authorizationUri(metadata.getAuthorizationEndpointURI().toASCIIString());
		}
		if (metadata.getTokenEndpointURI() != null) {
			builder.tokenUri(metadata.getTokenEndpointURI().toASCIIString());
		}
		return builder;
	}

	// The same choice as Spring Security's ClientRegistrations
	private static ClientAuthenticationMethod getClientAuthenticationMethod(
			@Nullable List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> methods) {
		if (methods == null
				|| methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		}
		if (methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		}
		if (methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
			return ClientAuthenticationMethod.NONE;
		}
		return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
	}

}
