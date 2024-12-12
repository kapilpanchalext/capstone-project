package com.java.oauth.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ProjectSecurityConfig {
	
	@Bean 
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.oidc(Customizer.withDefaults())
			)
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);

		return http.build();
	}
	
	@Bean 
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		
		CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = 
				new CsrfTokenRequestAttributeHandler();
		
		http
			.authorizeHttpRequests((authorize) -> authorize
              .anyRequest().authenticated())
//			.anonymous(anonymous -> anonymous.disable())
    		.cors(Customizer.withDefaults())

	        .csrf((csrfConfig) -> csrfConfig
	    		.ignoringRequestMatchers("/login")
	    		.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
	    		.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
			
//			.sessionManagement((sessionConfig) -> sessionConfig
//					.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
//			.addFilterBefore(new RequestCacheFilter(), UsernamePasswordAuthenticationFilter.class)
//			.addFilterBefore(new JwtTokenValidatorFilter(), BasicAuthenticationFilter.class)
//			.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//			.addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
//			.formLogin(flc -> flc.defaultSuccessUrl("http://localhost:8084/oauth2/token").permitAll());
			.formLogin(Customizer.withDefaults());
		
		return http.build();
	}
	
//	@Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .anyRequest().authenticated()
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
	
	@Bean 
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("capstone-project-1")
				.clientSecret("{noop}d4b282fd24ed88884fc21a3c1f9f0423af9452")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scopes((scopeConfig) -> scopeConfig.addAll(List.of(OidcScopes.OPENID, "ADMIN")))
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(1))
						.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
				.build();
		
		RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("capstone-project-auth-code-1")
				.clientSecret("{noop}d4b282fd24ed88884fc21a3c1f9f0423af9451")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.EMAIL)
				.tokenSettings(TokenSettings.builder()
						.refreshTokenTimeToLive(Duration.ofHours(8))
						.reuseRefreshTokens(false)
						.accessTokenTimeToLive(Duration.ofMinutes(1))
						.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
				.build();
		
		RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("capstone-project-auth-code-pkce-1")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://localhost:3000") //https://oauth.pstmn.io/v1/callback
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.EMAIL)
				.clientSettings(ClientSettings.builder().requireProofKey(true).build())
				.tokenSettings(TokenSettings.builder()
						.refreshTokenTimeToLive(Duration.ofHours(8))
						.reuseRefreshTokens(false)
						.accessTokenTimeToLive(Duration.ofHours(1))
						.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
				.build();

		return new InMemoryRegisteredClientRepository(clientCredClient, authCodeClient, pkceClient);
	}
	
	@Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
	
	@Bean 
	JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}
	
	private static KeyPair generateRsaKey() { 
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
	
	@Bean 
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(){
		return (context) -> {
			if(context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
				context.getClaims().claims((claims)->{
					if(context.getAuthorizationGrantType()
							.equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
						Set<String> roles = context.getClaims().build().getClaim("scope");
						claims.put("roles", roles);
					} else if(context.getAuthorizationGrantType()
							.equals(AuthorizationGrantType.AUTHORIZATION_CODE)){
						Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                                .stream()
                                .map(c -> c.replaceFirst("^ROLE_", ""))
                                .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                        claims.put("roles", roles);
					}
				});
			}
		};
	}
	
	@Bean 
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
    
}
