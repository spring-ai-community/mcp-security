package org.springaicommunity.mcp.security.server.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationProvider;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationConverter;
import org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
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
	void defaultSupportsCsrf() {
		var resp = this.mvc.post().uri("/default").header("X-API-key", "api01.test-secret");
		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");
	}

	@Test
	void defaultEnforcesCsrf() {
		assertThat(this.mvc.post().uri("/default/public")).hasStatus(HttpStatus.FORBIDDEN);
		assertThat(this.mvc.post().uri("/default/public").with(csrf())).hasStatus2xxSuccessful();
	}

	@Test
	void noApiKeyReturns401() {
		var resp = this.mvc.get().uri("/default");

		assertThat(resp).hasStatus(HttpStatus.UNAUTHORIZED);
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
	void customHeaderSupportsCsrf() {
		var resp = this.mvc.post().uri("/header").header("X-custom-API-key", "api01.test-secret");
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
	void customConverterSupportsCsrf() {
		var resp = this.mvc.get().uri("/converter").queryParam("apiKey", "api01.test-secret");
		assertThat(resp).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");
	}

	@Test
	void customConverterInvalidApiKey401() {
		var resp = this.mvc.get().uri("/converter").queryParam("apiKey", "invalid.invalid");

		assertThat(resp).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void sessionBindingEnforced() {
		var sessionId = java.util.UUID.randomUUID().toString();
		var initializeRequest = this.mvc.get()
			.uri("/default/session")
			.header("X-API-key", "api01.test-secret")
			.header("X-Set-Session-Id", sessionId);
		assertThat(initializeRequest).hasStatus2xxSuccessful().bodyText().isEqualTo("Hello api01");

		var validRequest = this.mvc.get()
			.uri("/default")
			.header("X-API-key", "api01.test-secret")
			.header(io.modelcontextprotocol.spec.HttpHeaders.MCP_SESSION_ID, sessionId);
		assertThat(validRequest).hasStatus(HttpStatus.OK);

		var invalidRequest = this.mvc.get()
			.uri("/default")
			.header("X-API-key", "api02.test-secret")
			.header(io.modelcontextprotocol.spec.HttpHeaders.MCP_SESSION_ID, sessionId);
		assertThat(invalidRequest).hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void postProcessors(@Autowired PostProcessorRecorder postProcessorRecorder) {
		assertThat(postProcessorRecorder.getPostProcessedClasses()).containsExactlyInAnyOrder(
				ApiKeyAuthenticationConverter.class, ApiKeyAuthenticationFilter.class,
				ApiKeyAuthenticationProvider.class);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebMvc
	@EnableWebSecurity
	static class TestConfig {

		@Bean
		PostProcessorRecorder postProcessedObjects() {
			return new PostProcessorRecorder();
		}

		@Bean
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, PostProcessorRecorder postProcessorRecorder) {
			return http.securityMatcher("/default/**").authorizeHttpRequests(authz -> {
				authz.requestMatchers("/default/public").permitAll();
				authz.anyRequest().authenticated();
			}).with(mcpServerApiKey(), apiKey -> {
				apiKey.apiKeyRepository(repo());
				apiKey.withObjectPostProcessor(postProcessorRecorder.getPostProcessor());
				apiKey.sessionBinding(Customizer.withDefaults());
			}).anonymous(Customizer.withDefaults()).build();
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
					List.of(ApiKeyEntityImpl.builder().id("api01").secret("test-secret").name("first key").build(),
							ApiKeyEntityImpl.builder().id("api02").secret("test-secret").name("second key").build()));
		}

		@Bean
		RouterFunction<?> routerFunction() {
			return RouterFunctions.route((req) -> true, req -> {
				var authentication = SecurityContextHolder.getContext().getAuthentication();
				var name = authentication != null ? authentication.getName() : "";
				var builder = ServerResponse.ok();
				var sessionId = req.headers().firstHeader("X-Set-Session-Id");
				if (sessionId != null) {
					builder.header(io.modelcontextprotocol.spec.HttpHeaders.MCP_SESSION_ID, sessionId);
				}
				return builder.body("Hello " + name);
			});
		}

	}

	static class PostProcessorRecorder {

		private final List<Class<?>> postProcessedClasses = new ArrayList<>();

		private ObjectPostProcessor<Object> getPostProcessor() {
			return new ObjectPostProcessor<>() {
				@Override
				public <O extends Object> O postProcess(O object) {
					postProcessedClasses.add(object.getClass());
					return object;
				}
			};
		}

		public List<Class<?>> getPostProcessedClasses() {
			return Collections.unmodifiableList(postProcessedClasses);
		}

	}

}
