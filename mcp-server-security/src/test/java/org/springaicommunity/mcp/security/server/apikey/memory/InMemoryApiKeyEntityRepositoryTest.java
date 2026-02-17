package org.springaicommunity.mcp.security.server.apikey.memory;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryApiKeyEntityRepositoryTest {

	private final ApiKeyEntityImpl apiKeyEntity = ApiKeyEntityImpl.builder()
		.id("api01")
		.secret("test-secret")
		.name("test key")
		.build();

	private final InMemoryApiKeyEntityRepository<@NonNull ApiKeyEntityImpl> repository = new InMemoryApiKeyEntityRepository<>(
			List.of(this.apiKeyEntity));

	@Test
	void loadsKey() {
		var key = this.repository.findByKeyId("api01");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(this.apiKeyEntity);
		assertThat(key.getId()).isEqualTo(this.apiKeyEntity.getId());
		assertThat(key.getSecret()).isEqualTo(this.apiKeyEntity.getSecret());
		assertThat(key.getName()).isEqualTo(this.apiKeyEntity.getName());
		assertThat(key.getAuthorities()).isEqualTo(this.apiKeyEntity.getAuthorities());
	}

	@Test
	void missingKey() {
		var key = this.repository.findByKeyId("does-not-exist");

		assertThat(key).isNull();
	}

	@Test
	void containsKey() {
		assertThat(this.repository.containsApiKey("api01")).isTrue();
		assertThat(this.repository.containsApiKey("does-not-exist")).isFalse();
	}

	@Test
	void addApiKey() {
		var addedKey = ApiKeyEntityImpl.builder().id("api02").secret("custom-secret").name("added key").build();

		this.repository.addApiKey(addedKey);
		var key = this.repository.findByKeyId("api02");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(addedKey);
		assertThat(key.getId()).isEqualTo(addedKey.getId());
		assertThat(key.getSecret()).isEqualTo(addedKey.getSecret());
		assertThat(key.getName()).isEqualTo(addedKey.getName());
		assertThat(key.getAuthorities()).isEqualTo(addedKey.getAuthorities());
	}

	@Test
	void addApiKeyOverrides() {
		var addedKey = ApiKeyEntityImpl.builder().id("api02").secret("custom-secret").name("added key").build();
		var addedKeyOverride = ApiKeyEntityImpl.builder().id("api02").secret("custom-secret").name("added key").build();

		this.repository.addApiKey(addedKey);
		this.repository.addApiKey(addedKeyOverride);
		var key = this.repository.findByKeyId("api02");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(addedKeyOverride);
		assertThat(key.getId()).isEqualTo(addedKeyOverride.getId());
		assertThat(key.getSecret()).isEqualTo(addedKeyOverride.getSecret());
		assertThat(key.getName()).isEqualTo(addedKeyOverride.getName());
		assertThat(key.getAuthorities()).isEqualTo(addedKeyOverride.getAuthorities());
	}

	@Test
	void removeApiKey() {
		this.repository.removeApiKey("api01");
		this.repository.removeApiKey("does-not-exist");

		assertThat(this.repository.containsApiKey("api01")).isFalse();
	}

}
