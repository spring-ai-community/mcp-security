package org.springaicommunity.mcp.security.server.config;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springaicommunity.mcp.security.server.config.McpApiKeyConfigurer.mcpServerApiKey;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
class McpApiKeyConfigurerTest {

	@Autowired
	WebApplicationContext wac;

	private MockMvcTester mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcTester.from(wac, builder -> builder.apply(springSecurity()).build());
	}

	@Test
	void validApiKey() {
		var resp = this.mvc.get().uri("/default").header("X-API-key", "api01.test-secret");
		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");
	}

	@Test
	void noApiKeyForbidden() {
		var resp = this.mvc.get().uri("/default");

		assertThat(resp).hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void otherAuthenticationPassthrough() {
		var resp = this.mvc.get().uri("/default").with(SecurityMockMvcRequestPostProcessors.user("test"));

		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello test");
	}

	@Test
	void customHeaderValidApiKey() {
		var resp = this.mvc.get().uri("/header").header("X-custom-API-key", "api01.test-secret");
		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");
	}

	@Test
	void customHeaderInvalidApiKey401() {
		var resp = this.mvc.get().uri("/header").header("X-custom-API-key", "invalid.invalid");

		assertThat(resp).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void customConverterValidApiKey() {
		var resp = this.mvc.get().uri("/converter").queryParam("apiKey", "api01.test-secret");
		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");
	}

	@Test
	void customConverterInvalidApiKey401() {
		var resp = this.mvc.get().uri("/converter").queryParam("apiKey", "invalid.invalid");

		assertThat(resp).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class TestConfig {

		@Bean
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
			return http.securityMatcher("/default/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerApiKey(), apiKey -> apiKey.apiKeyRepository(repo()))
				.build();
		}

		@Bean
		SecurityFilterChain customHeaderFilterChain(HttpSecurity http) throws Exception {
			return http.securityMatcher("/header/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerApiKey(), apiKey -> apiKey.apiKeyRepository(repo()).headerName("x-custom-api-key"))
				.build();
		}

		@Bean
		SecurityFilterChain customConverterSecurityFilterChain(HttpSecurity http) throws Exception {
			return http.securityMatcher("/converter/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerApiKey(), apiKey -> apiKey.apiKeyRepository(repo()).authenticationConverter((req) -> {
					var extractedKey = req.getParameter("apiKey");
					if (extractedKey == null) {
						return null;
					}
					return ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from(extractedKey));
				}))
				.build();
		}

		static ApiKeyEntityRepository<@NonNull ApiKeyEntity> repo() {
			return new InMemoryApiKeyEntityRepository<>(
					List.of(ApiKeyEntityImpl.builder().id("api01").secret("test-secret").name("first key").build()));
		}

		@Bean
		RouterFunction<?> routerFunction() {
			return RouterFunctions.route((req) -> true, req -> {
				var authentication = SecurityContextHolder.getContext().getAuthentication();
				var name = authentication.getName();
				return ServerResponse.ok().body("Hello " + name);
			});
		}

	}

}
