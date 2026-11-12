package org.springaicommunity.mcp.security.server.oauth2.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class BearerResourceMetadataTokenAuthenticationEntryPointTest {

	private final MockHttpServletRequest request = new MockHttpServletRequest();

	private final MockHttpServletResponse response = new MockHttpServletResponse();

	private final ResourceIdentifier resourceIdentifier = new ResourceIdentifier("/mcp");

	private final BearerResourceMetadataTokenAuthenticationEntryPoint entryPoint = new BearerResourceMetadataTokenAuthenticationEntryPoint(
			resourceIdentifier);

	@Test
	void commendThenWwwAuthenticateHeader() throws ServletException, IOException {
		AuthenticationException authException = mock(AuthenticationException.class);
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.isEqualTo("Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/mcp\"");
	}

	@Test
	void commenceWithCustomContextPathThenWwwAuthenticateHeader() throws Exception {
		request.setContextPath("/foo");
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setRequestURI("/foo/some/endpoint");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.isEqualTo("Bearer resource_metadata=\"https://example.com/foo/.well-known/oauth-protected-resource/mcp\"");

	}

	@Test
	void commenceWithDefaultContextPathThenWwwAuthenticateHeader() throws Exception {
		request.setContextPath("");
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setRequestURI("/some/endpoint");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.isEqualTo("Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/mcp\"");
	}

	@Test
	void commenceWithBearerHeaderExistingThenWwwAuthenticateHeader() throws Exception {
		request.setContextPath("");
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setRequestURI("/some/endpoint");
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.isEqualTo("Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/mcp\"");
	}

	@Test
	void commenceWithOAuth2ErrorPreservesAuthenticationParameters() throws Exception {
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);

		OAuth2Error error = new OAuth2Error("invalid_token", "Token expired", null);

		entryPoint.commence(request, response, new OAuth2AuthenticationException(error));

		assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
			.isEqualTo("Bearer error=\"invalid_token\", " + "error_description=\"Token expired\", "
					+ "resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/mcp\"");

		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	void replacesExistingResourceMetadataWithoutChangingOtherParameters() {
		String header = "Bearer error=\"invalid_token\", " + "resource_metadata=\"https://old.example/mcp\", "
				+ "scope=\"read\"";

		String result = BearerResourceMetadataTokenAuthenticationEntryPoint.withResourceMetadata(header,
				"https://new.example/mcp");

		assertThat(result).isEqualTo("Bearer error=\"invalid_token\", "
				+ "resource_metadata=\"https://new.example/mcp\", " + "scope=\"read\"");
	}

	@Test
	void doesNotReplaceSimilarlyNamedParameter() {
		String header = "Bearer other_resource_metadata=\"unchanged\", " + "error=\"invalid_token\"";

		String result = BearerResourceMetadataTokenAuthenticationEntryPoint.withResourceMetadata(header,
				"https://new.example/mcp");

		assertThat(result).isEqualTo("Bearer other_resource_metadata=\"unchanged\", " + "error=\"invalid_token\", "
				+ "resource_metadata=\"https://new.example/mcp\"");
	}

	@Test
	void replacesResourceMetadataCaseInsensitively() {
		String header = "Bearer RESOURCE_METADATA=\"https://old.example/mcp\", " + "error=\"invalid_token\"";

		String result = BearerResourceMetadataTokenAuthenticationEntryPoint.withResourceMetadata(header,
				"https://new.example/mcp");

		assertThat(result)
			.isEqualTo("Bearer resource_metadata=\"https://new.example/mcp\", " + "error=\"invalid_token\"");
	}

	@Test
	void replacementTreatsDollarSignAsLiteralText() {
		String result = BearerResourceMetadataTokenAuthenticationEntryPoint
			.withResourceMetadata("Bearer resource_metadata=\"https://old.example/mcp\"", "https://new.example/$mcp");

		assertThat(result).isEqualTo("Bearer resource_metadata=\"https://new.example/$mcp\"");
	}

	@Test
	void replacesResourceMetadataWithOptionalWhitespace() {
		String header = "Bearer error=\"invalid_token\", " + "resource_metadata = \"https://old.example/mcp\"";

		String result = BearerResourceMetadataTokenAuthenticationEntryPoint.withResourceMetadata(header,
				"https://new.example/mcp");

		assertThat(result)
			.isEqualTo("Bearer error=\"invalid_token\", " + "resource_metadata=\"https://new.example/mcp\"");
	}

}
