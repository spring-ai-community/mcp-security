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
package org.springaicommunity.mcp.security.server.oauth2.metadata;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * A representation of an OAuth 2.0 Protected Resource Metadata response, which is
 * returned from an OAuth 2.0 Resource Server's Metadata Endpoint, and contains a set of
 * claims about the Resource Server's configuration. The claims are defined by the OAuth
 * 2.0 Protected Resource Metadata specification (RFC 9728).
 *
 * @author Joe Grandja
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc9728.html#section-2">2.
 * Protected Resource Metadata</a>
 */
public final class OAuth2ProtectedResourceMetadata
		implements OAuth2ProtectedResourceMetadataClaimAccessor, Serializable {

	@Serial
	private static final long serialVersionUID = 229429735811566266L;

	private final Map<String, Object> claims;

	private OAuth2ProtectedResourceMetadata(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	public Map<String, Object> getClaims() {
		return this.claims;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		public Builder resource(String resource) {
			return claim(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE, resource);
		}

		public Builder authorizationServer(String authorizationServer) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS, authorizationServer);
			return this;
		}

		public Builder scope(String scope) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return this;
		}

		public Builder bearerMethod(String bearerMethod) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED, bearerMethod);
			return this;
		}

		public Builder resourceName(String resourceName) {
			return claim(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME, resourceName);
		}

		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		public OAuth2ProtectedResourceMetadata build() {
			validate();
			return new OAuth2ProtectedResourceMetadata(this.claims);
		}

		private void validate() {
			Assert.notNull(this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE),
					"resource cannot be null");
			validateURL(this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE),
					"resource must be a valid URL");
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS),
						"authorization_servers must be of type List");
				Assert.notEmpty(
						(List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS),
						"authorization_servers cannot be empty");
				List<?> authorizationServers = (List<?>) this.claims
					.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS);
				authorizationServers.forEach(authorizationServer -> validateURL(authorizationServer,
						"authorization_server must be a valid URL"));
			}
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes cannot be empty");
			}
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED),
						"bearer methods must be of type List");
				Assert.notEmpty(
						(List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED),
						"bearer methods cannot be empty");
			}
		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.computeIfAbsent(name, (k) -> new LinkedList<String>());
			((List<String>) this.claims.get(name)).add(value);
		}

		private static void validateURL(Object url, String errorMessage) {
			if (URL.class.isAssignableFrom(url.getClass())) {
				return;
			}

			try {
				new URI(url.toString()).toURL();
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}

	}

}
