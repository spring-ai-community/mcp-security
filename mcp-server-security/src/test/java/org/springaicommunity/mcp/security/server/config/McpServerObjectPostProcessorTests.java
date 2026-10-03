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
package org.springaicommunity.mcp.security.server.config;

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.server.oauth2.authentication.BearerResourceMetadataTokenAuthenticationEntryPoint;
import org.springaicommunity.mcp.security.server.oauth2.jwt.AudienceValidationJwtDecoder;
import org.springaicommunity.mcp.security.server.web.OriginValidationFilter;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.CorsFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpServerObjectPostProcessorTests {

	private static final String ISSUER = "https://auth.example.com";

	@Test
	void postProcessesCreatedComponentsWithoutProcessingSuppliedDecoder() {
		var processed = new ArrayList<Object>();
		var configurer = configurer().validateAudienceClaim(true);
		configurer.allowedOrigins(List.of("https://allowed.example.com"));
		configurer.withObjectPostProcessor(new ObjectPostProcessor<Object>() {
			@Override
			public <O> O postProcess(O object) {
				processed.add(object);
				return object;
			}
		});

		var fixture = new ResourceServerFixture();
		configurer.init(fixture.http);

		assertThat(processed).extracting(Object::getClass)
			.containsExactlyInAnyOrder(BearerResourceMetadataTokenAuthenticationEntryPoint.class,
					AudienceValidationJwtDecoder.class, OriginValidationFilter.class);
	}

	@Test
	void usesPostProcessedAuthenticationEntryPoint() {
		var replacement = mock(AuthenticationEntryPoint.class);
		var configurer = configurer();
		configurer.withObjectPostProcessor(replacing(AuthenticationEntryPoint.class, replacement));
		var fixture = new ResourceServerFixture();

		configurer.init(fixture.http);

		verify(fixture.resourceServer).authenticationEntryPoint(replacement);
	}

	@Test
	void usesPostProcessedAudienceDecoder() {
		var replacement = mock(JwtDecoder.class);
		var configurer = configurer().validateAudienceClaim(true);
		configurer.withObjectPostProcessor(replacing(JwtDecoder.class, replacement));
		var fixture = new ResourceServerFixture();

		configurer.init(fixture.http);

		verify(fixture.jwt).decoder(replacement);
	}

	@Test
	void usesPostProcessedOriginFilterAndPreservesOriginValidation() throws Exception {
		var configurer = configurer();
		configurer.allowedOrigins(List.of("https://allowed.example.com"));
		configurer.withObjectPostProcessor(new ObjectPostProcessor<Filter>() {
			@Override
			@SuppressWarnings("unchecked")
			public <O extends Filter> O postProcess(O object) {
				Filter decorated = (request, response, chain) -> {
					((jakarta.servlet.http.HttpServletResponse) response).setHeader("X-Post-Processed", "true");
					object.doFilter(request, response, chain);
				};
				return (O) decorated;
			}
		});
		var fixture = new ResourceServerFixture();
		configurer.init(fixture.http);
		var filter = ArgumentCaptor.forClass(Filter.class);
		verify(fixture.http).addFilterAfter(filter.capture(), eq(CorsFilter.class));
		var request = new MockHttpServletRequest("GET", "/mcp");
		request.addHeader(HttpHeaders.ORIGIN, "https://evil.example.com");
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();

		filter.getValue().doFilter(request, response, chain);

		assertThat(response.getHeader("X-Post-Processed")).isEqualTo("true");
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(chain.getRequest()).isNull();
	}

	@Test
	void postProcessesDefaultDecoder() {
		var original = mock(NimbusJwtDecoder.class);
		var replacement = mock(JwtDecoder.class);
		var builder = mock(NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder.class);
		when(builder.build()).thenReturn(original);
		var configurer = new McpServerOAuth2Configurer().authorizationServer(ISSUER);
		configurer.withObjectPostProcessor(replacing(JwtDecoder.class, replacement));
		var fixture = new ResourceServerFixture();

		try (var factory = mockStatic(NimbusJwtDecoder.class)) {
			factory.when(() -> NimbusJwtDecoder.withIssuerLocation(ISSUER)).thenReturn(builder);
			configurer.init(fixture.http);
		}

		verify(fixture.jwt).decoder(replacement);
	}

	@Test
	void preservesSuppliedDecoderWithoutAudienceValidation() {
		var original = mock(JwtDecoder.class);
		var replacement = mock(JwtDecoder.class);
		var configurer = configurer().jwtDecoder(original);
		configurer.withObjectPostProcessor(replacing(JwtDecoder.class, replacement));
		var fixture = new ResourceServerFixture();

		configurer.init(fixture.http);

		verify(fixture.jwt).decoder(original);
	}

	private McpServerOAuth2Configurer configurer() {
		return new McpServerOAuth2Configurer().authorizationServer(ISSUER).jwtDecoder(mock(JwtDecoder.class));
	}

	private <T> ObjectPostProcessor<Object> replacing(Class<T> type, T replacement) {
		return new ObjectPostProcessor<>() {
			@Override
			@SuppressWarnings("unchecked")
			public <O> O postProcess(O object) {
				return type.isInstance(object) ? (O) replacement : object;
			}
		};
	}

	private static class ResourceServerFixture {

		private final HttpSecurity http = mock(HttpSecurity.class);

		@SuppressWarnings("unchecked")
		private final OAuth2ResourceServerConfigurer<HttpSecurity> resourceServer = mock(
				OAuth2ResourceServerConfigurer.class);

		private final OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwt = mock(
				OAuth2ResourceServerConfigurer.JwtConfigurer.class);

		ResourceServerFixture() {
			doAnswer(invocation -> {
				Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
				customizer.customize(this.resourceServer);
				return this.http;
			}).when(this.http).oauth2ResourceServer(any());
			doAnswer(invocation -> {
				Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer> customizer = invocation
					.getArgument(0);
				customizer.customize(this.jwt);
				return this.resourceServer;
			}).when(this.resourceServer).jwt(any());
		}

	}

}
