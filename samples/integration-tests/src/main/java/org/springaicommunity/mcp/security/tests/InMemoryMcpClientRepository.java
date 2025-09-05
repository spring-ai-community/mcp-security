package org.springaicommunity.mcp.security.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.spec.McpSchema;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.stereotype.Component;

@Component
public class InMemoryMcpClientRepository {

	private final Map<String, McpSyncClient> clients = new HashMap<>();

	private final ObjectMapper objectMapper;

	private final McpClientCommonProperties commonProperties;

	private final McpSyncHttpClientRequestCustomizer requestCustomizer;

	public InMemoryMcpClientRepository(List<McpSyncClient> clients, ObjectMapper objectMapper,
			McpSyncHttpClientRequestCustomizer requestCustomizer, McpClientCommonProperties commonProperties) {
		this.objectMapper = objectMapper;
		this.commonProperties = commonProperties;
		this.requestCustomizer = requestCustomizer;
		for (var client : clients) {
			var name = client.getClientInfo().name();
			this.clients.putIfAbsent(name.replace(commonProperties.getName() + " - ", ""), client);
		}
	}

	public List<McpSyncClient> getClients() {
		return new ArrayList<>(this.clients.values());
	}

	public McpSyncClient getClientByName(String name) {
		return this.clients.get(name);
	}

	public List<String> getClientNames() {
		return new ArrayList<>(this.clients.keySet());
	}

	public void addClient(String url, String name) {
		var transport = HttpClientStreamableHttpTransport.builder(url)
			.clientBuilder(HttpClient.newBuilder())
			.objectMapper(objectMapper)
			.httpRequestCustomizer(requestCustomizer)
			.build();

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

	public void removeClient(String url) {
		var client = clients.remove(url);
		if (client != null) {
			client.closeGracefully();
		}
	}

}
