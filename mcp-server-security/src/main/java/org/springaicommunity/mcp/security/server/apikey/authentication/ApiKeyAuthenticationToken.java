package org.springaicommunity.mcp.security.server.apikey.authentication;

import java.util.Collection;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKey;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;

@Transient
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

	@Nullable
	private final ApiKeyEntity principal;

	@Nullable
	private final ApiKey credentials;

	private ApiKeyAuthenticationToken(ApiKey apiKey) {
		super(null);
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
	@Nullable
	public ApiKey getCredentials() {
		return this.credentials;
	}

	@Override
	@Nullable
	public ApiKeyEntity getPrincipal() {
		return this.principal;
	}

	@Override
	public String getName() {
		return this.credentials != null ? this.credentials.getId() : this.principal.getId();
	}

}