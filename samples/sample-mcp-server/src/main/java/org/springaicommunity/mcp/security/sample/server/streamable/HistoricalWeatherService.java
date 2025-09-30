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

package org.springaicommunity.mcp.security.sample.server.streamable;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import org.springaicommunity.mcp.annotation.McpTool;

import org.springframework.ai.tool.annotation.ToolParam;
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

	@McpTool(name = "temperature-history",
			description = "Get 5-year historical temperature data (in Celsius), including daily min and daily max temperatures, for a specific location")
	public ToolResponse getHistoricalWeatherData(@ToolParam(description = "The location latitude") double latitude,
			@ToolParam(description = "The location longitude") double longitude) {

		var data = IntStream.range(0, 5)
			.parallel()
			.mapToObj(yearDelta -> getWeatherData(latitude, longitude, yearDelta))
			.flatMap(List::stream)
			.toList();

		return new ToolResponse(data);
	}

	/**
	 * Obtain weather data at the given location, N years ago, for +/- 2 days. For
	 * example, if today is 2025-09-28, and N years = 2 years, will return weather data
	 * for 2023-09-26 through 2023-09-30.
	 */
	private List<ToolResponse.DailyTemperatures> getWeatherData(double latitude, double longitude, int yearsAgo) {
		var response = restClient.get()
			.uri("https://archive-api.open-meteo.com/v1/archive?latitude={latitude}&longitude={longitude}&start_date={start}&end_date={end}&daily=temperature_2m_min,temperature_2m_max",
			//@formatter:off
				Map.of(
						"latitude", latitude,
						"longitude", longitude,
						"start", LocalDate.now().minus(Period.ofYears(yearsAgo)).minus(Period.ofDays(2)),
						"end", yearsAgo == 0 ? LocalDate.now() : LocalDate.now().minus(Period.ofYears(yearsAgo)).plus(Period.ofDays(2))
				)
			//@formatter:on
			)
			.retrieve()
			.body(HistoricalWeatherApiResponse.class);
		var entries = response.daily().time().length;
		//@formatter:off
        return IntStream.range(0, entries)
                .mapToObj(i -> new ToolResponse.DailyTemperatures(
                        response.daily().time()[i].toString(),
                        response.daily().temperature_2m_min()[i],
                        response.daily().temperature_2m_max()[i]
                ))
                .toList();
        //@formatter:on
	}

}
