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
package org.springaicommunity.mcp.security.tests.common.server;

import java.util.List;

import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;

import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.DelegatingRegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.ClientIdMetadataDocumentRegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.ClientIdUrlValidator;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.DefaultClientIdMetadataDocumentResolver;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.DefaultClientMetadataValidator;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import static org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer;

@Configuration
@EnableWebSecurity
public class AuthorizationServer {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(mcpAuthorizationServer(), authzServer -> authzServer.dynamicClientRegistration(true).cimd(true))
			.formLogin(Customizer.withDefaults())
			// MCP inspector
			.cors(cors -> cors.configurationSource(new AllowAllCorsConfigurationSource()))
			.csrf(CsrfConfigurer::disable)
			.build();
	}

	@Bean
	DelegatingRegisteredClientRepository repository(OAuth2AuthorizationServerProperties properties) {
		var mapper = new OAuth2AuthorizationServerPropertiesMapper(properties);
		var cimdRepository = new ClientIdMetadataDocumentRegisteredClientRepository();
		var resolver = new DefaultClientIdMetadataDocumentResolver();
		cimdRepository.setMetadataDocumentResolver(resolver);
		cimdRepository.setMetadataValidator(new DefaultClientMetadataValidator(new DefaultUrlValidator(true)));
		cimdRepository.setClientIdUrlValidator(new ClientIdUrlValidator(true));
		var dcrRepository = new InMemoryRegisteredClientRepository(mapper.asRegisteredClients());
		return new DelegatingRegisteredClientRepository(List.of(cimdRepository, dcrRepository), dcrRepository);
	}

}
