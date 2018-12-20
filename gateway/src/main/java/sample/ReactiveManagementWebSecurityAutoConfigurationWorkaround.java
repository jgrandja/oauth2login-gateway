/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.health.HealthEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.info.InfoEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;

@Configuration
@ConditionalOnClass({ EnableWebFluxSecurity.class, WebFilterChainProxy.class })
@ConditionalOnMissingBean({ SecurityWebFilterChain.class, WebFilterChainProxy.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@AutoConfigureBefore(ReactiveSecurityAutoConfiguration.class)
@AutoConfigureAfter({ HealthEndpointAutoConfiguration.class,
		InfoEndpointAutoConfiguration.class, WebEndpointAutoConfiguration.class,
		ReactiveOAuth2ClientAutoConfiguration.class })
class ReactiveManagementWebSecurityAutoConfigurationWorkaround {

	// NOTE: This code duplicates ReactiveManagementWebSecurityAutoConfiguration and enhances with oauth2Login() specific configuration

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		return http
					.authorizeExchange()
						.matchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class)).permitAll()
						.anyExchange().authenticated()
						.and()
					.httpBasic()
						.and()
					.formLogin()
						.and()
					.oauth2Login()
						.and()
					.exceptionHandling()
						// NOTE:
						// This configuration is needed to perform the auto-redirect to UAA for authentication.
						// Leaving this out will result in a default login page with option for formLogin() and link for UAA for oauth2Login()
						.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"))
						.and()
					.build();
		// @formatter:on
	}
}