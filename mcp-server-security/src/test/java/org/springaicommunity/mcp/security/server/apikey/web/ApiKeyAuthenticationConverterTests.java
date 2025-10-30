package org.springaicommunity.mcp.security.server.apikey.web;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiKeyAuthenticationConverterTests {

	private final ApiKeyAuthenticationConverter converter = new ApiKeyAuthenticationConverter("x-custom-header");

	@Test
	void convertExtractsApiKey() {
		var request = new MockHttpServletRequest();
		request.addHeader("x-custom-header", "api01.my-secret");

		var authentication = converter.convert(request);
		assertThat(authentication).isInstanceOf(ApiKeyAuthenticationToken.class);
		var apiKey = (ApiKeyAuthenticationToken) authentication;
		assertThat(apiKey.isAuthenticated()).isFalse();
		assertThat(apiKey.getPrincipal()).isNull();
		assertThat(apiKey.getCredentials().getId()).isEqualTo("api01");
		assertThat(apiKey.getCredentials().getSecret()).isEqualTo("my-secret");
	}

	@Test
	void convertWhenNoHeaderReturnsNull() {
		var request = new MockHttpServletRequest();

		var authentication = converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	void convertWhenEmptyHeaderReturnsNull() {
		var request = new MockHttpServletRequest();
		request.addHeader("x-custom-header", "");

		var authentication = converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	void convertWhenMalformedThrows() {
		var request = new MockHttpServletRequest();
		request.addHeader("x-custom-header", "wrong-format");

		assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(BadCredentialsException.class)
			.hasMessage("API key must be in the format <id>.<secret>");
	}

	@Test
	void convertWhenMultipleApiKeysThrows() {
		var request = new MockHttpServletRequest();
		request.addHeader("x-custom-header", "api01.my-secret");
		request.addHeader("x-custom-header", "api02.my-secret");

		assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(BadCredentialsException.class)
			.hasMessage("x-custom-header must have a single value, found 2");
	}

	@Test
	void constructorWhenHeaderBlankThenThrows() {
		assertThatThrownBy(() -> new ApiKeyAuthenticationConverter("")).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("apiKeyHeaderName cannot be blank");
	}

}
