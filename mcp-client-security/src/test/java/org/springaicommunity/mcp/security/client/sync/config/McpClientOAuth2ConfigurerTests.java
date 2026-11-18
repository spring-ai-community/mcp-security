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
package org.springaicommunity.mcp.security.client.sync.config;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2DcrClientManager;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpClientOAuth2ConfigurerTests {

	@Test
	void configuredBaseUrlIsUsedInCimdDocument() throws Exception {
		String json = cimdDocument(new McpClientOAuth2Configurer().baseUrl("https://public.example.com"));

		assertThat(json)
			.contains("https://public.example.com/test/client-id-metadata.json",
					"https://public.example.com/authorize/oauth2/code/test")
			.doesNotContain("internal.example.com");
	}

	@Test
	void requestBaseUrlIsUsedWhenNoBaseUrlIsConfigured() throws Exception {
		String json = cimdDocument(new McpClientOAuth2Configurer());

		assertThat(json).contains("http://internal.example.com:8080/test/client-id-metadata.json",
				"http://internal.example.com:8080/authorize/oauth2/code/test");
	}

	private String cimdDocument(McpClientOAuth2Configurer configurer) throws Exception {
		try (var context = new StaticApplicationContext()) {
			context.getBeanFactory().registerSingleton("clientManager", mock(McpOAuth2DcrClientManager.class));
			var http = mock(HttpSecurity.class);
			when(http.getSharedObject(ApplicationContext.class)).thenReturn(context);
			when(http.getSharedObject(ClientRegistrationRepository.class))
				.thenReturn(new InMemoryMcpClientRegistrationRepository());

			configurer.init(http);

			var filter = ArgumentCaptor.forClass(Filter.class);
			verify(http).addFilterBefore(filter.capture(), eq(ExceptionTranslationFilter.class));
			var request = new MockHttpServletRequest("GET", "/test/client-id-metadata.json");
			request.setServerName("internal.example.com");
			request.setServerPort(8080);
			var response = new MockHttpServletResponse();
			filter.getValue().doFilter(request, response, new MockFilterChain());
			assertThat(response.getStatus()).isEqualTo(200);
			return response.getContentAsString();
		}
	}

}
