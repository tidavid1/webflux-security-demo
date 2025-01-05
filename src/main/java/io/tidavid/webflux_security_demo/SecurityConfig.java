package io.tidavid.webflux_security_demo;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity httpSecurity) {
        return httpSecurity
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .logout(ServerHttpSecurity.LogoutSpec::disable)
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .anyExchange().authenticated()
            ).build();
    }

    /*
     * CORS 필터 설정
     * CORS 설정을 위한 CorsConfiguration 객체를 생성하고, 허용할 Origin, Method, Header, MaxAge를 설정한다.
     * HttpMethod.OPTIONS 요청에 대해서는 permitAll()을 해야한다.
     */
    @Bean
    CorsWebFilter corsWebFilter() {
        return new CorsWebFilter(exchange -> {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(
                List.of("http://localhost:3000", "http://localhost:3001"));
            configuration.addAllowedMethod("*");
            configuration.addAllowedHeader("*");
            configuration.setMaxAge(86_400L);
            return configuration;
        });
    }

}
