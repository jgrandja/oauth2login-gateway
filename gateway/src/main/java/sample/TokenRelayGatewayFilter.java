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

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class TokenRelayGatewayFilter implements GatewayFilter {
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	public TokenRelayGatewayFilter(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		firewall(exchange);
		return exchange.getPrincipal()
				.cast(OAuth2AuthenticationToken.class)
				.flatMap(authentication -> authorizedClient(exchange, authentication))
				.map(OAuth2AuthorizedClient::getAccessToken)
				.map(token -> withBearerAuth(exchange, token))
				.defaultIfEmpty(exchange)
				.flatMap(chain::filter);
	}

	private void firewall(ServerWebExchange exchange) {
		List<String> authzHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
		if (!CollectionUtils.isEmpty(authzHeaders) && authzHeaders.stream().anyMatch(h -> h.equalsIgnoreCase("Bearer"))) {
			throw new IllegalStateException("Malicious Client is trying to submit Bearer Authorization header");
		}
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ServerWebExchange exchange, OAuth2AuthenticationToken oauth2Authentication) {
		return this.authorizedClientRepository.loadAuthorizedClient(
				oauth2Authentication.getAuthorizedClientRegistrationId(), oauth2Authentication, exchange);
	}

	private ServerWebExchange withBearerAuth(ServerWebExchange exchange, OAuth2AccessToken accessToken) {
		return exchange.mutate()
				.request(r -> r.headers(headers -> headers.setBearerAuth(accessToken.getTokenValue())))
				.build();
	}
}