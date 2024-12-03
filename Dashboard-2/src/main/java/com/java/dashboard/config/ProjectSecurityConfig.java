package com.java.dashboard.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.java.dashboard.filter.CsrfCookieFilter;


@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

	@Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new RoleConverter());

		CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = 
				new CsrfTokenRequestAttributeHandler();

        http
        	.sessionManagement((sessionConfig) -> sessionConfig
        											.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        	.cors(withDefaults())
            .csrf((csrfConfig) -> csrfConfig
        		.ignoringRequestMatchers("/api/v1/**")
        		.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
        		.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
            .authorizeHttpRequests((requests) -> 
                requests.requestMatchers("/api/v1/**").hasAnyRole("ADMIN")
                		.requestMatchers("/home**", "/about", "/contact").permitAll())
            .oauth2ResourceServer((rsc) -> rsc.jwt((jwtConfigurer) -> 
            		jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
