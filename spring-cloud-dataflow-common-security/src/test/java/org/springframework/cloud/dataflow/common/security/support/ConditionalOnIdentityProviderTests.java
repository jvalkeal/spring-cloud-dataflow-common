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
package org.springframework.cloud.dataflow.common.security.support;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.cloud.dataflow.common.security.support.ConditionalOnIdentityProvider.Type;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for
 * {@link ConditionalOnIdentityProvider @ConditionalOnIdentityProvider}.
 *
 * @author Janne Valkealahti
 */
public class ConditionalOnIdentityProviderTests {

	private ConfigurableApplicationContext context;
	private ConfigurableEnvironment environment = new StandardEnvironment();

	@AfterEach
	void tearDown() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	void azureTenantIdDefined() {
		load(AzureTenantIdConfiguration.class, "azure.activedirectory.tenant-id=xxx-xxx");
		assertThat(this.context.containsBean("foo")).isTrue();
	}

	@Test
	void azureTenantIdDefinedWithOauth2Properties() {
		load(AzureTenantIdConfiguration.class, "azure.activedirectory.tenant-id=xxx-xxx",
				"spring.security.oauth2.client.registration.foo.provider=bar");
		assertThat(this.context.containsBean("foo")).isTrue();
	}

	@Test
	void azureTenantIdDefinedWithOauth2PropertiesNoLegacyMatch() {
		load(LegacyConfiguration.class, "azure.activedirectory.tenant-id=xxx-xxx",
				"spring.security.oauth2.client.registration.foo.provider=bar");
		assertThat(this.context.containsBean("foo")).isFalse();
	}

	@Test
	void someOauth2PropertiesDefined() {
		load(LegacyConfiguration.class, "spring.security.oauth2.client.registration.foo.provider=bar");
		assertThat(this.context.containsBean("foo")).isTrue();
	}

	@Test
	void noSecurityPropertiesDefined() {
		load(NoProviderConfiguration.class);
		assertThat(this.context.containsBean("foo")).isTrue();
	}

	private void load(Class<?> config, String... environment) {
		TestPropertyValues.of(environment).applyTo(this.environment);
		this.context = new SpringApplicationBuilder(config).environment(this.environment).web(WebApplicationType.NONE)
				.run();
	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnIdentityProvider(type = Type.AZUREAD)
	static class AzureTenantIdConfiguration {

		@Bean
		String foo() {
			return "foo";
		}
	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnIdentityProvider(type = Type.LEGACY)
	static class LegacyConfiguration {

		@Bean
		String foo() {
			return "foo";
		}
	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnIdentityProvider(type = Type.NONE)
	static class NoProviderConfiguration {

		@Bean
		String foo() {
			return "foo";
		}
	}
}
