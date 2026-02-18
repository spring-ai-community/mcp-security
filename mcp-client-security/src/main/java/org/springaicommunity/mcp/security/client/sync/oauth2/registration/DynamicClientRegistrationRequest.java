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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

import java.util.Collections;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.util.Assert;

/**
 * Represents a base request for OAuth2 Dynamic Client registration.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.1">RFC7591 - 3.1
 * Client Registration Request</a>
 */
public class DynamicClientRegistrationRequest {

	private final List<AuthorizationGrantType> grantTypes;

	@Nullable private final List<String> redirectUris;

	@Nullable private final ClientAuthenticationMethod tokenEndpointAuthMethod;

	@Nullable private final List<OAuth2AuthorizationResponseType> responseTypes;

	@Nullable private final String clientName;

	@Nullable private final String clientUri;

	@Nullable private final String scope;

	private DynamicClientRegistrationRequest(List<AuthorizationGrantType> grantTypes,
			@Nullable List<String> redirectUris, @Nullable ClientAuthenticationMethod tokenEndpointAuthMethod,
			@Nullable List<OAuth2AuthorizationResponseType> responseTypes, @Nullable String clientName,
			@Nullable String clientUri, @Nullable String scope) {
		this.grantTypes = Collections.unmodifiableList(grantTypes);
		this.redirectUris = redirectUris != null ? Collections.unmodifiableList(redirectUris) : null;
		this.responseTypes = responseTypes != null ? Collections.unmodifiableList(responseTypes) : null;
		this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
		this.clientName = clientName;
		this.clientUri = clientUri;
		this.scope = scope;
	}

	public List<AuthorizationGrantType> getGrantTypes() {
		return this.grantTypes;
	}

	@Nullable public List<String> getRedirectUris() {
		return this.redirectUris;
	}

	@Nullable public ClientAuthenticationMethod getTokenEndpointAuthMethod() {
		return this.tokenEndpointAuthMethod;
	}

	@Nullable public List<OAuth2AuthorizationResponseType> getResponseTypes() {
		return this.responseTypes;
	}

	@Nullable public String getClientName() {
		return this.clientName;
	}

	@Nullable public String getClientUri() {
		return this.clientUri;
	}

	@Nullable public String getScope() {
		return this.scope;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder from(DynamicClientRegistrationRequest other) {
		Assert.notNull(other, "source request must not be null");
		Builder builder = new Builder();
		builder.grantTypes = other.grantTypes;
		builder.redirectUris = other.redirectUris;
		builder.tokenEndpointAuthMethod = other.tokenEndpointAuthMethod;
		builder.responseTypes = other.responseTypes;
		builder.clientName = other.clientName;
		builder.clientUri = other.clientUri;
		builder.scope = other.scope;
		return builder;
	}

	@Override
	public String toString() {
		return "DynamicClientRegistrationRequest{" + "grantTypes=" + grantTypes + ", redirectUris=" + redirectUris
				+ ", tokenEndpointAuthMethod=" + tokenEndpointAuthMethod + ", responseTypes=" + responseTypes
				+ ", clientName='" + clientName + '\'' + ", clientUri='" + clientUri + '\'' + ", scope='" + scope + '\''
				+ '}';
	}

	public static class Builder {

		@Nullable private List<AuthorizationGrantType> grantTypes;

		@Nullable private List<String> redirectUris;

		@Nullable private ClientAuthenticationMethod tokenEndpointAuthMethod;

		@Nullable private List<OAuth2AuthorizationResponseType> responseTypes;

		@Nullable private String clientName;

		@Nullable private String clientUri;

		@Nullable private String scope;

		private Builder() {
		}

		public Builder redirectUris(List<String> redirectUris) {
			this.redirectUris = redirectUris;
			return this;
		}

		public Builder grantTypes(List<AuthorizationGrantType> grantTypes) {
			Assert.notEmpty(grantTypes, "grantTypes cannot be empty");
			this.grantTypes = grantTypes;
			return this;
		}

		public Builder tokenEndpointAuthMethod(ClientAuthenticationMethod tokenEndpointAuthMethod) {
			this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
			return this;
		}

		public Builder responseTypes(List<OAuth2AuthorizationResponseType> responseTypes) {
			this.responseTypes = responseTypes;
			return this;
		}

		public Builder clientName(String clientName) {
			this.clientName = clientName;
			return this;
		}

		public Builder clientUri(String clientUri) {
			this.clientUri = clientUri;
			return this;
		}

		public Builder scope(List<String> scopes) {
			Assert.notNull(scopes, "scope cannot be null");
			this.scope = String.join(" ", scopes);
			return this;
		}

		public Builder scope(String scope) {
			this.scope = scope;
			return this;
		}

		public DynamicClientRegistrationRequest build() {
			if (this.grantTypes == null) {
				this.grantTypes = List.of(AuthorizationGrantType.CLIENT_CREDENTIALS);
			}
			if (this.grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
				Assert.notEmpty(this.redirectUris,
						"redirectUris must not be null or empty when grant type contains authorization_code");
				if (this.responseTypes == null) {
					this.responseTypes = List.of(OAuth2AuthorizationResponseType.CODE);
				}
			}
			if (this.grantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
				Assert.isTrue(this.grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE),
						"grant types must contain authorization_code when refresh_token is present");
			}
			return new DynamicClientRegistrationRequest(this.grantTypes, this.redirectUris,
					this.tokenEndpointAuthMethod, this.responseTypes, this.clientName, this.clientUri, this.scope);
		}

	}

}
