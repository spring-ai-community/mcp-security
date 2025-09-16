package org.springaicommunity.mcp.security.sample.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.stereotype.Repository;

@Repository
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
		var transport = HttpClientStreamableHttpTransport.builder(url)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(new JacksonMcpJsonMapper(objectMapper))
			.httpRequestCustomizer(requestCustomizer)
			.build();

		var clientInfo = new McpSchema.Implementation("spring-ai-mcp-client - " + name, commonProperties.getVersion());

		var client = McpClient.sync(transport)
			.clientInfo(clientInfo)
			.requestTimeout(commonProperties.getRequestTimeout())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();

		clients.put(url, client);
	}

	public void removeSseClient(String url) {
		var client = clients.remove(url);
		if (client != null) {
			client.closeGracefully();
		}
	}

}
