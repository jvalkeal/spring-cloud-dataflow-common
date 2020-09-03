package org.springframework.cloud.dataflow.common.security.azure;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.cloud.dataflow.common.security.AuthorizationProperties;
import org.springframework.cloud.dataflow.common.security.ProviderRoleMapping;
import org.springframework.cloud.dataflow.common.security.SecurityState;
import org.springframework.cloud.dataflow.common.security.support.ConditionalOnIdentityProvider;
import org.springframework.cloud.dataflow.common.security.support.MappingGrantedAuthoritiesMapper;
import org.springframework.cloud.dataflow.common.security.support.MappingJwtGrantedAuthoritiesConverter;
import org.springframework.cloud.dataflow.common.security.support.SecurityConfigUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.util.StringUtils;

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@ConditionalOnMissingBean(WebSecurityConfigurerAdapter.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.ANY)
@EnableWebSecurity
@ConditionalOnIdentityProvider(type = ConditionalOnIdentityProvider.Type.AZUREAD)
public class AzureADOAuthSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(AzureADOAuthSecurityConfiguration.class);

	@Autowired
	protected OAuth2ClientProperties oauth2ClientProperties;

	@Autowired
	protected SecurityState securityStateBean;

	@Autowired
	protected AuthorizationProperties authorizationProperties;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		this.authorizationProperties.getAuthenticatedPaths().add("/");
		this.authorizationProperties.getAuthenticatedPaths().add(dashboard("/**"));
		this.authorizationProperties.getAuthenticatedPaths().add(this.authorizationProperties.getDashboardUrl());
		this.authorizationProperties.getPermitAllPaths().add(this.authorizationProperties.getDashboardUrl());
		this.authorizationProperties.getPermitAllPaths().add(dashboard("/**"));
		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry security =

		http.authorizeRequests()
			.antMatchers(this.authorizationProperties.getPermitAllPaths().toArray(new String[0]))
			.permitAll()
			.antMatchers(this.authorizationProperties.getAuthenticatedPaths().toArray(new String[0]))
			.authenticated();
		security = SecurityConfigUtils.configureSimpleSecurity(security, this.authorizationProperties);
		security.anyRequest().denyAll();


		http.httpBasic().and()
				.logout()
				// .logoutSuccessHandler(logoutSuccessHandler())
				.and().csrf().disable()
				.exceptionHandling()
				// for UI not to send basic auth header
				.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"))
				// .defaultAuthenticationEntryPointFor(
				// 		new LoginUrlAuthenticationEntryPoint(this.authorizationProperties.getLoginProcessingUrl()),
				// 		textHtmlMatcher)
				// .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint, AnyRequestMatcher.INSTANCE)
				;

		MappingGrantedAuthoritiesMapper mmm = new MappingGrantedAuthoritiesMapper();
		String providerId = calculateDefaultProviderId();
		mmm.setAuthoritiesMapping(authorizationProperties.getGrantedAuthoritiesMappings().get(providerId).getAuthoritiesMappings());


		http.oauth2Login()
			.userInfoEndpoint()
			.userAuthoritiesMapper(mmm)
			;
		// http.oauth2Login().userInfoEndpoint()
		// 	.userService(this.plainOauth2UserService())
		// 	.oidcUserService(this.oidcUserService());

		// if (opaqueTokenIntrospector != null) {
		// 	http.oauth2ResourceServer()
		// 		.opaqueToken()
		// 			.introspector(opaqueTokenIntrospector());
		// } else if (oAuth2ResourceServerProperties.getJwt().getJwkSetUri() != null) {
		// 	http.oauth2ResourceServer()
		// 		.jwt()
		// 			.jwtAuthenticationConverter(grantedAuthoritiesExtractor());
		// }

		http.oauth2ResourceServer()
			.jwt()
				.jwtAuthenticationConverter(grantedAuthoritiesExtractor());

		this.securityStateBean.setAuthenticationEnabled(true);
    }

	protected Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
		String providerId = calculateDefaultProviderId();
		ProviderRoleMapping providerRoleMapping = authorizationProperties.getProviderRoleMappings().get(providerId);

		JwtAuthenticationConverter jwtAuthenticationConverter =
				new JwtAuthenticationConverter();

		MappingJwtGrantedAuthoritiesConverter converter = new MappingJwtGrantedAuthoritiesConverter();
		converter.setAuthorityPrefix("");
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(converter);
		if (providerRoleMapping != null) {
			converter.setAuthoritiesMapping(providerRoleMapping.getRoleMappings());
		}
		return jwtAuthenticationConverter;
	}

	protected String dashboard(String path) {
		return this.authorizationProperties.getDashboardUrl() + path;
	}

    private String calculateDefaultProviderId() {
		if (this.authorizationProperties.getDefaultProviderId() != null) {
			return this.authorizationProperties.getDefaultProviderId();
		}
		else if (this.oauth2ClientProperties.getRegistration().size() == 1) {
			return this.oauth2ClientProperties.getRegistration().entrySet().iterator().next().getKey();
		}
		else if (this.oauth2ClientProperties.getRegistration().size() > 1
				&& StringUtils.isEmpty(this.authorizationProperties.getDefaultProviderId())) {
			throw new IllegalStateException("defaultProviderId must be set if more than 1 Registration is provided.");
		}
		else {
			throw new IllegalStateException("Unable to retrieve default provider id.");
		}
	}
}
