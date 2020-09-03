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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link MappingGrantedAuthoritiesMapper}.
 *
 * @author Janne Valkealahti
 */
public class MappingGrantedAuthoritiesMapperTests {

	private static SimpleGrantedAuthority rolea = new SimpleGrantedAuthority("ROLE_a");
	private static SimpleGrantedAuthority roleb = new SimpleGrantedAuthority("ROLE_b");
	private static SimpleGrantedAuthority rolec = new SimpleGrantedAuthority("ROLE_c");
	private static SimpleGrantedAuthority roled = new SimpleGrantedAuthority("ROLE_d");
	private static SimpleGrantedAuthority rolee = new SimpleGrantedAuthority("ROLE_e");
	private static SimpleGrantedAuthority rolef = new SimpleGrantedAuthority("ROLE_f");

	@Test
	public void testNoMapping() {
		MappingGrantedAuthoritiesMapper mapper = new MappingGrantedAuthoritiesMapper();
		List<SimpleGrantedAuthority> from = Arrays.asList(rolea, roleb);
		Collection<? extends GrantedAuthority> to = mapper.mapAuthorities(Arrays.asList(rolea, roleb));
		assertThat(to).isEqualTo(from);
	}

	@Test
	public void testMapping() {
		MappingGrantedAuthoritiesMapper mapper = new MappingGrantedAuthoritiesMapper();
		Map<String, String> authoritiesMapping = new HashMap<>();
		authoritiesMapping.put("ROLE_e", "ROLE_c");
		authoritiesMapping.put("ROLE_f", "ROLE_d");
		mapper.setAuthoritiesMapping(authoritiesMapping);
		List<GrantedAuthority> from = Arrays.asList(rolea, roleb, rolec, roled);
		Collection<? extends GrantedAuthority> to = mapper.mapAuthorities(from);
		List<GrantedAuthority> result = to.stream().collect(Collectors.toList());
		assertThat(result).containsExactlyInAnyOrderElementsOf(Arrays.asList(rolee, rolef));
	}
}
