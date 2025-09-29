package org.springaicommunity.mcp.security.server.apikey.authentication;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public class ApiKeyAuthenticationProvider<T extends ApiKeyEntity> implements AuthenticationProvider {

	private final ApiKeyEntityRepository<T> apiKeyEntityRepository;

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository) {
		Assert.notNull(apiKeyEntityRepository, "apiKeyRepository cannot be null");
		this.apiKeyEntityRepository = apiKeyEntityRepository;
	}

	@Override
	public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		ApiKeyAuthenticationToken apiKeyToken = (ApiKeyAuthenticationToken) authentication;
		var apiKey = apiKeyToken.getCredentials();

		if (apiKey == null) {
			throw new BadCredentialsException("API key is null");
		}

		T loggedInEntity = this.apiKeyEntityRepository.findByKeyId(apiKey.getId());
		if (loggedInEntity == null) {
			throw new BadCredentialsException("Invalid API key");
		}
		if (!passwordEncoder.matches(apiKey.getSecret(), loggedInEntity.getSecret())) {
			throw new BadCredentialsException("API key does not match");
		}

		return ApiKeyAuthenticationToken.authenticated(loggedInEntity, loggedInEntity.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

}