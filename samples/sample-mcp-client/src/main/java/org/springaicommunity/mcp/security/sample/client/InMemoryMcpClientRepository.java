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

package org.springaicommunity.mcp.security.sample.client;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.stereotype.Repository;

/**
 * @author Daniel Garnier-Moiroux
 */
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

	public void addClient(String url, String name) {
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

}
