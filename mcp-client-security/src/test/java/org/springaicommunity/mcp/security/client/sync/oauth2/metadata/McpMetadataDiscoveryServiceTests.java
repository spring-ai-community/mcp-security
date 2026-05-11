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
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link McpMetadataDiscoveryService}.
 */
class McpMetadataDiscoveryServiceTests {

	@Test
	void getProtectedResourceMetadataValidatesUrl() throws InvalidUrlException {
		UrlValidator urlValidator = mock(UrlValidator.class);
		doThrow(new InvalidUrlException("Invalid URL", "http://bad")).when(urlValidator).validateUrl(anyString());

		McpMetadataDiscoveryService service = new McpMetadataDiscoveryService(RestClient.builder().build(),
				urlValidator);

		assertThatThrownBy(() -> service.getProtectedResourceMetadata("http://bad"))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Invalid MCP resource metadata url: Invalid URL");

		verify(urlValidator).validateUrl("http://bad");
	}

}
