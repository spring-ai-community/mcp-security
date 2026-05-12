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

import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
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
	void validateUrl() throws InvalidUrlException {
		UrlValidator urlValidator = mock(UrlValidator.class);
		doThrow(new InvalidUrlException("Invalid URL", "http://bad")).when(urlValidator).validateUrl(anyString());

		McpMetadataDiscoveryService service = new McpMetadataDiscoveryService(RestClient.builder().build(),
				urlValidator);

		assertThatThrownBy(() -> service.getProtectedResourceMetadata("http://bad"))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Invalid MCP resource metadata url: Invalid URL");

		verify(urlValidator).validateUrl("http://bad");
	}

	@Test
	void convertHttpResponse() {
		var rcBuilder = RestClient.builder();
		var mockServer = MockRestServiceServer.bindTo(rcBuilder).build();
		var client = rcBuilder.build();
		var sampleResponse = """
				{
					"resource": "https://resource.example.com/mcp",
					"authorization_servers": ["https://as1.example.com",  "https://as2.example.net"],
					"bearer_methods_supported": ["header", "body"],
					"scopes_supported": ["profile", "email", "phone"],
					"resource_documentation": "https://resource.example.com/resource_documentation.html"
				}
				""";

		mockServer.expect(MockRestRequestMatchers.requestTo("https://resource.example.com/mcp"))
			.andRespond(MockRestResponseCreators.withUnauthorizedRequest()
				.header("WWW-Authenticate",
						"Bearer resource=https://resource.example.com/.well-known/oauth-protected-resource/mcp"));
		mockServer
			.expect(MockRestRequestMatchers
				.requestTo("https://resource.example.com/.well-known/oauth-protected-resource/mcp"))
			.andRespond(MockRestResponseCreators.withSuccess(sampleResponse, MediaType.APPLICATION_JSON));

		var service = new McpMetadataDiscoveryService(client, url -> {
		});
		var response = service.getMcpMetadata("https://resource.example.com/mcp");

		assertThat(response.protectedResourceMetadata().resource()).isEqualTo("https://resource.example.com/mcp");
		assertThat(response.protectedResourceMetadata().authorizationServers())
			.containsExactly("https://as1.example.com", "https://as2.example.net");
		assertThat(response.protectedResourceMetadata().scopesSupported()).containsExactly("profile", "email", "phone");
	}

}
