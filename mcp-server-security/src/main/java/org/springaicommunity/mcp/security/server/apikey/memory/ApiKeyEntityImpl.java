package org.springaicommunity.mcp.security.server.apikey.memory;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public class ApiKeyEntityImpl implements ApiKeyEntity {

	private final String id;

	@Nullable
	private String secret;

	private final String name;

	private ApiKeyEntityImpl(String id, @Nullable String secret, String name) {
		this.id = id;
		this.secret = secret;
		this.name = name;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public @Nullable String getSecret() {
		return secret;
	}

	public String getName() {
		return name;
	}

	@Override
	public void eraseCredentials() {
		this.secret = null;
	}

	@Override
	public ApiKeyEntityImpl copy() {
		return new ApiKeyEntityImpl(this.id, this.secret, this.name);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {

		@Nullable
		private String id;

		@Nullable
		private String secret;

		@Nullable
		private String name;

		private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		private Builder() {
		}

		public Builder passwordEncoder(PasswordEncoder encoder) {
			this.passwordEncoder = passwordEncoder;
			return this;
		}

		public Builder id(String id) {
			Assert.hasText(id, "id must not be blank");
			this.id = id;
			return this;
		}

		public Builder secret(String secret) {
			Assert.hasText(secret, "secret must not be blank");
			this.secret = secret;
			return this;
		}

		public Builder name(String name) {
			Assert.hasText(name, "name must not be blank");
			this.name = name;
			return this;
		}

		public ApiKeyEntityImpl build() {
			Assert.hasText(id, "id must not be blank");
			Assert.hasText(secret, "secret must not be blank");
			Assert.hasText(name, "name must not be blank");
			return new ApiKeyEntityImpl(id, this.passwordEncoder.encode(secret), name);
		}

	}

}
