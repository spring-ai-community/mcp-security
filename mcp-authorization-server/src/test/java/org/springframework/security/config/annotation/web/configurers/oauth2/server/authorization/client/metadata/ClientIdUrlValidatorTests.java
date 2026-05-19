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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ClientIdUrlValidator}
 *
 * @author Daniel Garnier-Moiroux
 */
class ClientIdUrlValidatorTests {

	private final ClientIdUrlValidator validator = new ClientIdUrlValidator(false);

	@Test
	void valid() {
		assertThatNoException().isThrownBy(() -> validator.validateUrl("https://example.com/client-id.json"));
	}

	@Test
	void allowLoobpack() {
		var validator = new ClientIdUrlValidator(true);
		assertThatNoException().isThrownBy(() -> validator.validateUrl("http://localhost:1234/client-id.json"));
	}

	@Test
	void emptyPath() {
		assertThatThrownBy(() -> validator.validateUrl("https://example.com")).isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("must have a path component");
	}

	@Test
	void hasFragment() {
		assertThatThrownBy(() -> validator.validateUrl("https://example.com/client-id.json#fragment"))
			.isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("must not have a fragment component");
	}

	@Test
	void hasUserInfo() {
		assertThatThrownBy(() -> validator.validateUrl("https://user:pass@example.com/client-id.json"))
			.isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("must not contain a username or password");
	}

}
