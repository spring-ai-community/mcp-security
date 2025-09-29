package org.springaicommunity.mcp.security.tests.common.tests;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

public abstract class ApiKeysAbstractTests {

	protected abstract McpClientTransport buildUnauthenticatedTransport();

	protected abstract McpClientTransport buildAuthenticatedTransport();

	@Test
	public void notAuthenticated() {
		var mcpClientBuilder = McpClient.sync(buildUnauthenticatedTransport())
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			assertThatThrownBy(mcpClient::initialize).hasMessage("Client failed to initialize by explicit API call")
				.rootCause()
				// Note: this should be better handled by the Java-SDK.
				// Today, the HTTP 401 response is wrapped in a RuntimeException with
				// a poor String representation.
				.isInstanceOf(RuntimeException.class)
				.satisfiesAnyOf(e -> {
					// message with http client
					assertThat(e).hasMessageStartingWith("Failed to send message: DummyEvent");
				}, e -> {
					// message with webclient
					assertThat(e).hasMessageStartingWith("401 Unauthorized from POST");
				});
		}
		catch (Exception e) {
			fail(e);
		}
	}

	@Test
	public void authenticated() {
		var mcpClientBuilder = McpClient.sync(buildAuthenticatedTransport())
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			var resp = mcpClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

			assertThat(resp.content()).hasSize(1)
				.first()
				.asInstanceOf(type(McpSchema.TextContent.class))
				.extracting(McpSchema.TextContent::text)
				// the "sub" of the token used in the request is the client id, in
				// client_credentials
				.isEqualTo("Hello api01");
		}
		catch (Exception e) {
			fail(e);
		}
	}

}
