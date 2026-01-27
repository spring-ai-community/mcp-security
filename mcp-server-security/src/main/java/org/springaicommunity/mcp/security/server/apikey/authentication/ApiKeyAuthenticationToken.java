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

package org.springaicommunity.mcp.security.server.apikey.authentication;

import java.util.Collection;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKey;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Daniel Garnier-Moiroux
 */
@Transient
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

	@Nullable private final ApiKeyEntity principal;

	@Nullable private final ApiKey credentials;

	private ApiKeyAuthenticationToken(ApiKey apiKey) {
		super(AuthorityUtils.NO_AUTHORITIES);
		this.principal = null;
		this.credentials = apiKey;
		setAuthenticated(false);
	}

	private ApiKeyAuthenticationToken(ApiKeyEntity principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = null;
		setAuthenticated(true);
	}

	public static ApiKeyAuthenticationToken unauthenticated(ApiKey apiKey) {
		return new ApiKeyAuthenticationToken(apiKey);
	}

	public static ApiKeyAuthenticationToken authenticated(ApiKeyEntity principal,
			Collection<? extends GrantedAuthority> authorities) {
		return new ApiKeyAuthenticationToken(principal, authorities);
	}

	@Override
	@Nullable public ApiKey getCredentials() {
		return this.credentials;
	}

	@Override
	@Nullable public ApiKeyEntity getPrincipal() {
		return this.principal;
	}

	@Override
	public String getName() {
		return this.credentials != null ? this.credentials.getId() : this.principal.getId();
	}

}