package org.springaicommunity.mcp.security.tests;

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;

import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Import({ InMemoryMcpClientRepository.class, McpController.class })
@EnableWebSecurity
class McpClientConfiguration {

	@Bean
	McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
		return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
	}

	@Bean
	McpSyncClientCustomizer syncClientCustomizer() {
		return (name, syncSpec) -> syncSpec.transportContextProvider(new AuthenticationMcpTransportContextProvider());
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
			.oauth2Client(Customizer.withDefaults())
			.build();
	}

}
