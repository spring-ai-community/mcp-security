package org.springaicommunity.mcp.security.sample.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.WebClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2AuthorizationCodeExchangeFilterFunction;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.stereotype.Repository;
import org.springframework.web.reactive.function.client.WebClient;

@Repository
public class InMemoryMcpClientRepository {

	private final Map<String, McpSyncClient> clients = new HashMap<>();

	private final ObjectMapper objectMapper;

	private final McpClientCommonProperties commonProperties;

	private final WebClient.Builder webClientBuilder;

	public InMemoryMcpClientRepository(List<McpSyncClient> clients, ObjectMapper objectMapper,
			McpClientCommonProperties commonProperties,
			@Qualifier("mcpWebClientBuilder") WebClient.Builder webClientBuilder) {
		this.objectMapper = objectMapper;
		this.commonProperties = commonProperties;
		this.webClientBuilder = webClientBuilder.clone();
		for (McpSyncClient c : clients) {
			this.clients.put(c.getClientInfo().name(), c);
		}
	}

	public List<McpSyncClient> getClients() {
		return new ArrayList<>(this.clients.values());
	}

	public List<String> getClientNames() {
		return new ArrayList<>(this.clients.keySet());
	}

	public void addSseClient(String url, String name) {
		var builder = webClientBuilder.baseUrl(url);
		var transport = WebClientStreamableHttpTransport.builder(builder).objectMapper(objectMapper).build();

		var clientInfo = new McpSchema.Implementation("spring-ai-mcp-client - " + name, commonProperties.getVersion());

		var client = McpClient.sync(transport)
			.clientInfo(clientInfo)
			.requestTimeout(commonProperties.getRequestTimeout())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();

		try {
			client.initialize();
		}
		catch (RuntimeException e) {
			// We expect the nested reactive calls to propagate the inner exceptions to
			// be able to propagate them back up to the Servlet filter chain; they will
			// be intercepted and trigger OAuth2 authorization flows.
			if (e.getCause() instanceof ClientAuthorizationRequiredException crae) {
				throw crae;
			}
			throw e;
		}
		clients.put(url, client);
	}

	public void removeSseClient(String url) {
		var client = clients.remove(url);
		if (client != null) {
			client.closeGracefully();
		}
	}

}
