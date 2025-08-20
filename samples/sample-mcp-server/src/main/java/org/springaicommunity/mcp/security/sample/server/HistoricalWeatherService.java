/*
 * Copyright 2025 - 2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.sample.server;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * @author Daniel Garnier-Moiroux
 */
@Service
public class HistoricalWeatherService {

	private final RestClient restClient;

	public HistoricalWeatherService() {
		this.restClient = RestClient.create();
	}

	/**
	 * The response format from the Open-Meteo API
	 */
	public record HistoricalWeatherApiResponse(Daily daily) {
		public record Daily(LocalDate[] time, double[] temperature_2m_max, double[] temperature_2m_min) {
		}
	}

	public record ToolResponse(List<DailyTemperatures> dailyTemperatures) {
		public record DailyTemperatures(String date, double minTemperature, double maxTemperature) {
		}
	}

	@Tool(description = "Get 5-year historical temperature data, daily min and daily max, for a specific location")
	public ToolResponse getHistoricalWeatherData(@ToolParam(description = "The location latitude") double latitude,
			@ToolParam(description = "The location longitude") double longitude, ToolContext toolContext) {

		HistoricalWeatherApiResponse response = restClient.get()
			.uri("https://archive-api.open-meteo.com/v1/archive?latitude={latitude}&longitude={longitude}&start_date={start}&end_date={end}&daily=temperature_2m_min,temperature_2m_max",
			//@formatter:off
				Map.of(
						"latitude", latitude,
						"longitude", longitude,
						"start", LocalDate.now().minus(Period.ofYears(5)),
						"end", LocalDate.now()
				)
			//@formatter:on
			)

			.retrieve()
			.body(HistoricalWeatherApiResponse.class);
		var entries = response.daily().time().length;
		//@formatter:off
		var mapped = IntStream.range(0, entries)
				.mapToObj(i -> new ToolResponse.DailyTemperatures(
						response.daily().time()[i].toString(),
						response.daily().temperature_2m_min()[i],
						response.daily().temperature_2m_max()[i]
				))
				.toList();
		//@formatter:on

		return new ToolResponse(mapped);

	}

}
