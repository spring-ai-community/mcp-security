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

package org.springaicommunity.mcp.security.common.url;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DefaultUrlValidator}.
 */
class DefaultUrlValidatorTest {

	@Test
	void valid() {
		DefaultUrlValidator validator = new DefaultUrlValidator();
		Assertions.assertThatNoException().isThrownBy(() -> validator.validateUrl("https://example.com"));
	}

	@Test
	void invalid() {
		DefaultUrlValidator validator = new DefaultUrlValidator();
		assertThatThrownBy(() -> validator.validateUrl("http://example.com")).isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("URL http://example.com must have HTTPS scheme");
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://localhost", "http://127.0.0.1", "http://[::1]", "http://localhost:8080",
			"http://127.0.0.1:9090", "http://[::1]:3000" })
	void loopbackAddress(String url) {
		DefaultUrlValidator allowLoopbackValidator = new DefaultUrlValidator(true);
		DefaultUrlValidator noLoopbackValidator = new DefaultUrlValidator();
		Assertions.assertThatNoException().isThrownBy(() -> allowLoopbackValidator.validateUrl(url));
		assertThatThrownBy(() -> noLoopbackValidator.validateUrl(url)).isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("URL %s must have HTTPS scheme".formatted(url));
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://[127.0.0.1]", "http://example.com/spaces here", "://example.com" })
	void malformedUrls(String url) {
		DefaultUrlValidator validator = new DefaultUrlValidator();
		assertThatThrownBy(() -> validator.validateUrl(url)).isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("Cannot parse url");
	}

	@ParameterizedTest
	@ValueSource(strings = { "ftp://example.com", "ws://example.com", "wss://example.com", "file:///etc/passwd",
			"ldap://example.com", "gopher://example.com" })
	void nonHttpOrHttpsUrls(String url) {
		DefaultUrlValidator validator = new DefaultUrlValidator();
		assertThatThrownBy(() -> validator.validateUrl(url)).isInstanceOf(InvalidUrlException.class)
			.hasMessageContaining("must have HTTPS scheme");
	}

}
