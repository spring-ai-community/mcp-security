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

package org.springaicommunity.mcp.security.client.sync.oauth2.metadata;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class WwwAuthenticateParametersTests {

	@Test
	void parseBearerChallenge() {
		String header = "Bearer resource_metadata=\"https://example.com/resource\","
				+ " realm=\"example\", scope=\"openid\", error=\"invalid_token\","
				+ " error_description=\"The token has expired\"";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getParameter("resource_metadata")).isEqualTo("https://example.com/resource");
		assertThat(result.getParameter("realm")).isEqualTo("example");
		assertThat(result.getParameter("scope")).isEqualTo("openid");
		assertThat(result.getParameter("error")).isEqualTo("invalid_token");
		assertThat(result.getParameter("error_description")).isEqualTo("The token has expired");
		assertThat(result.getParameter("nonexistent")).isNull();
	}

	@Test
	void parseBearerWithResourceMetadataOnly() {
		String header = "Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource\"";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/.well-known/oauth-protected-resource");
		assertThat(result.getScope()).isNull();
		assertThat(result.getError()).isNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "Bearer resource_metadata=\"https://example.com/resource\"",
			"Bearer resource_metadata=https://example.com/resource",
			"bearer resource_metadata=\"https://example.com/resource\"",
			"BEARER resource_metadata=\"https://example.com/resource\"",
			"  Bearer   resource_metadata=\"https://example.com/resource\"  " })
	void parseBearerResourceMetadataVariants(String header) {
		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/resource");
	}

	@Test
	void parseReturnsNullForNonBearerScheme() {
		String header = "Basic realm=\"example\"";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNull();
	}

	@Test
	void parseReturnsNullForDigestScheme() {
		String header = "Digest realm=\"example\", nonce=\"abc123\"";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNull();
	}

	@Test
	void parseReturnsNullWhenNoResourceMetadata() {
		String header = "Bearer realm=\"example\", scope=\"read write\"";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNull();
	}

	@Test
	void parseReturnsNullForEmptyString() {
		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse("");

		assertThat(result).isNull();
	}

	@Test
	void parseReturnsNullForMalformedHeader() {
		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse("not-a-valid-header");

		assertThat(result).isNull();
	}

	@Test
	void parseBearerWithMultipleUnquotedParameters() {
		String header = "Bearer resource_metadata=https://example.com/resource, error=insufficient_scope, scope=read";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/resource");
		assertThat(result.getError()).isEqualTo("insufficient_scope");
		assertThat(result.getScope()).isEqualTo("read");
	}

	@Test
	void parseBearerWithExtraWhitespace() {
		String header = "  Bearer   resource_metadata=\"https://example.com/resource\"  ,  scope=\"read\"  ";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/resource");
		assertThat(result.getScope()).isEqualTo("read");
	}

	@Test
	void parseBearerAndBasicChallengesExtractsOnlyBearerParameters() {
		String header = "Bearer resource_metadata=\"https://example.com/resource\", type=Bearer,"
				+ " Basic realm=\"example\", type=Basic";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/resource");
		assertThat(result.getParameter("type")).isEqualTo("Bearer");
		assertThat(result.getParameter("realm")).isNull();
	}

	@Test
	void parseBasicThenBearerChallengesExtractsOnlyBearerParameters() {
		String header = "Basic realm=\"example\", type=Basic,"
				+ " Bearer resource_metadata=\"https://example.com/resource\", type=Bearer";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://example.com/resource");
		assertThat(result.getParameter("type")).isEqualTo("Bearer");
		assertThat(result.getParameter("realm")).isNull();
	}

	@Test
	void parseMultipleBearerChallengesExtractsOnlyFirstParameter() {
		String header = "Bearer resource_metadata=\"https://one.example.com/resource\", type=Bearer, "
				+ " Bearer resource_metadata=\"https://two.com/resource\", number=Two";

		WwwAuthenticateParameters result = WwwAuthenticateParameters.parse(header);

		assertThat(result).isNotNull();
		assertThat(result.getResourceMetadata()).isEqualTo("https://one.example.com/resource");
		assertThat(result.getParameter("number")).isNull();
		assertThat(result.getParameter("type")).isEqualTo("Bearer");
	}

}
