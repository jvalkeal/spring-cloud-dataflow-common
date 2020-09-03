/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.cloud.dataflow.common.security;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthorizationProperties}.
 *
 * @author Janne Valkealahti
 */
public class AuthorizationPropertiesTests {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

	@Test
	public void testAuthoritiesMappings() {
		this.contextRunner
		.withInitializer(context -> {
			Map<String, Object> map = new HashMap<>();
			map.put("test.granted-authorities-mappings.provider1.authorities-mappings.ROLE_a", "ROLE_aa");
			context.getEnvironment().getPropertySources().addLast(new SystemEnvironmentPropertySource(
				StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, map));
			})
			.withUserConfiguration(Config1.class)
			.run((context) -> {
				AuthorizationProperties properties = context.getBean(AuthorizationProperties.class);
				assertThat(properties.getGrantedAuthoritiesMappings()).hasSize(1);
				assertThat(properties.getGrantedAuthoritiesMappings().get("provider1")).isNotNull();
				assertThat(properties.getGrantedAuthoritiesMappings().get("provider1").getAuthoritiesMappings())
						.hasSize(1);
				assertThat(properties.getGrantedAuthoritiesMappings().get("provider1").getAuthoritiesMappings()
						.get("ROLE_a")).isEqualTo("ROLE_aa");
				});
	}

	@EnableConfigurationProperties
	private static class Config1 {

		@Bean
		@ConfigurationProperties(prefix = "test")
		public AuthorizationProperties authorizationProperties() {
			return new AuthorizationProperties();
		}
	}
}
