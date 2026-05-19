package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata;

import java.net.URI;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class DefaultClientIdMetadataDocumentResolverTest {

	private MockRestServiceServer server;

	private DefaultClientIdMetadataDocumentResolver resolver;

	private static final String CLIENT_JSON = """
			{
			  "client_id": "test-client",
			  "client_name": "Test Client",
			  "grant_types": ["authorization_code"]
			}
			""";

	@BeforeEach
	void setUp() {
		var builder = RestClient.builder()
			.configureMessageConverters((messageConverters) -> messageConverters
				.addCustomConverter(new OAuth2ClientRegistrationHttpMessageConverter()));
		server = MockRestServiceServer.bindTo(builder).build();
		resolver = new DefaultClientIdMetadataDocumentResolver(builder.build());
	}

	@Test
	void resolve() throws Exception {
		URI clientId = new URI("https://example.com/client");

		server.expect(MockRestRequestMatchers.requestTo(clientId))
			.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON));

		ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

		assertThat(result).isNotNull();
		assertThat(result.clientRegistration()).isNotNull();
		assertThat(result.clientRegistration().getClientId()).isEqualTo("test-client");
		assertThat(result.clientRegistration().getClientName()).isEqualTo("Test Client");
		assertThat(result.clientRegistration().getGrantTypes())
			.containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(300);
		server.verify();
	}

	@Test
	void localhost() throws Exception {
		URI clientId = new URI("http://localhost:1234/client");

		server.expect(MockRestRequestMatchers.requestTo(clientId))
			.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON));

		ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

		assertThat(result).isNotNull();
		assertThat(result.clientRegistration().getClientId()).isEqualTo("test-client");
		server.verify();
	}

	@Test
	void emptyBody() throws Exception {
		URI clientId = new URI("https://example.com/client");

		server.expect(MockRestRequestMatchers.requestTo(clientId))
			.andRespond(MockRestResponseCreators.withSuccess("", MediaType.APPLICATION_JSON));

		assertThatExceptionOfType(InvalidClientMetadataException.class).isThrownBy(() -> resolver.resolve(clientId))
			.withMessageContaining("Client metadata response must not have an empty body");
		server.verify();
	}

	@Nested
	class CacheControl {

		@Test
		void noStore() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "no-store"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(-1);
			server.verify();
		}

		@Test
		void maxAge() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "max-age=100"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(100);
			server.verify();
		}

		@Test
		void maxAgeZero() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "max-age=0"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(-1);
			server.verify();
		}

		@Test
		void maxAgeTooLong() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "max-age=100000"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(86400);
			server.verify();
		}

		@Test
		void multipleDirectives() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "public, max-age=3600"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(3600);
			server.verify();
		}

		@Test
		void negative() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "max-age=-10"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(300);
			server.verify();
		}

		@Test
		void missingMaxAge() throws Exception {
			URI clientId = new URI("https://example.com/client");

			server.expect(MockRestRequestMatchers.requestTo(clientId))
				.andRespond(MockRestResponseCreators.withSuccess(CLIENT_JSON, MediaType.APPLICATION_JSON)
					.header(HttpHeaders.CACHE_CONTROL, "public"));

			ClientIdMetadataDocumentResolver.Result result = resolver.resolve(clientId);

			assertThat(result.responseAttributes().cacheMaxAgeSeconds()).isEqualTo(300);
			server.verify();
		}

	}

}
