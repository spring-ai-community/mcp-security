/*
 * Copyright 2025-2025 the original author or authors.
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
package org.springaicommunity.mcp.security.sample.authorizationserver;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ClientRegistrationEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.ResourceIdentifierAudienceTokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.UriComponentsBuilder;
import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.authorizationServer;

@Configuration
@EnableWebSecurity
class AuthorizationServerConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(authorizationServer(), authServer -> {
				authServer.oidc(Customizer.withDefaults());
				authServer.authorizationServerMetadataEndpoint(
						authorizationServerMetadataEndpoint -> authorizationServerMetadataEndpoint
							.authorizationServerMetadataCustomizer(authorizationServerMetadataCustomizer()));
			})
			.with(new OAuth2ClientRegistrationEndpointConfigurer(), Customizer.withDefaults())
			.formLogin(Customizer.withDefaults())
			// MCP inspector
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			// dgarnier
			.csrf(csrf -> csrf.ignoringRequestMatchers(
					OAuth2ClientRegistrationEndpointConfigurer.OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI))
			.build();
	}

	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOriginPatterns(List.of("*"));
		configuration.setAllowedMethods(List.of("*"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	private static Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer() {
		return (builder) -> {
			AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
			String issuer = authorizationServerContext.getIssuer();

			String clientRegistrationEndpoint = UriComponentsBuilder.fromUriString(issuer)
				.path(OAuth2ClientRegistrationEndpointConfigurer.OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI)
				.build()
				.toUriString();

			builder.clientRegistrationEndpoint(clientRegistrationEndpoint);
		};
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		jwtGenerator.setJwtCustomizer(new ResourceIdentifierAudienceTokenCustomizer());
		return jwtGenerator;
	}

}
