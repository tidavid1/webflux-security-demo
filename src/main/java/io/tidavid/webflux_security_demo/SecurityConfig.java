package io.tidavid.webflux_security_demo;

import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity httpSecurity) {
        return httpSecurity
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .logout(ServerHttpSecurity.LogoutSpec::disable)
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .anyExchange().permitAll()
            )
            .exceptionHandling(exceptionHandlingSpec -> {
                exceptionHandlingSpec.authenticationEntryPoint((exchange, e) -> {
                    log.error("Authentication Error", e);
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatusCode.valueOf(401));
                    /*
                     * RFC-6750 참조
                     * https://datatracker.ietf.org/doc/html/rfc6750
                     * `WWW-Authenticate` 헤더에 스키마를 통해 인증 응답 반환
                     * realm: 인증을 요구하는 리소스의 범위를 나타냄 (ex. 도메인)
                     * error: 인증 오류의 종류를 나타냄 (ex. invalid_token, insufficient_scope)
                     * error_description: 인증 오류에 대한 상세 설명
                     * error_uri: 인증 오류에 대한 상세 설명을 제공하는 URI
                     */
                    response.getHeaders()
                        .set("WWW-Authenticate", "Basic realm=\"Webflux Security Demo\"");

                    return response.setComplete();
                });
                exceptionHandlingSpec.accessDeniedHandler((exchange, e) -> {
                    log.error("Access Denied", e);
                    exchange.getResponse().setStatusCode(HttpStatusCode.valueOf(403));
                    return exchange.getResponse().setComplete();
                });
            })
            .addFilterAt(customWebFilter1(), SecurityWebFiltersOrder.LAST)
            .addFilterAt(customWebFilter2(), SecurityWebFiltersOrder.LAST)
            .addFilterAt(customWebFilter3(), SecurityWebFiltersOrder.LAST)
            .build();
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

    /*
     * WebFilter 구현체는 등록 순서대로 체이닝됨
     * WebFilter 1에서 Authentication 객체를 생성하고, ReactiveSecurityContextHolder에 설정한다.
     * `@Bean`으로 등록하면 자동으로 WebFilterChain에 등록된다. SecurityFilterChain이 아님에 주의
     */
    WebFilter customWebFilter1() {
        return (exchange, chain) -> {
            log.info("Method: {}, Path: {}", exchange.getRequest().getMethod(),
                exchange.getRequest().getPath());
            log.info("WebFilter 1 Start");
            Authentication authentication = new Authentication() {
                @Override
                public String getName() {
                    return "이름 테스트";
                }

                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return List.of();
                }

                @Override
                public Object getCredentials() {
                    return 1L;
                }

                @Override
                public Object getDetails() {
                    return null;
                }

                @Override
                public Object getPrincipal() {
                    return null;
                }

                @Override
                public boolean isAuthenticated() {
                    return false;
                }

                @Override
                public void setAuthenticated(boolean isAuthenticated)
                    throws IllegalArgumentException {
                    throw new UnsupportedOperationException();
                }
            };
            log.info("WebFilter 1 End");
            return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        };
    }

    /*
     * WebFilter 2에서 Principal 정보를 출력한다.
     * `@Bean`으로 등록하면 자동으로 WebFilterChain에 등록된다. SecurityFilterChain이 아님에 주의
     */
    WebFilter customWebFilter2() {
        return (exchange, chain) -> {
            log.info("WebFilter 2 Start");
            return exchange.getPrincipal()
                .map(principal -> {
                    log.info("Principal Name: {}", principal.getName());
                    return principal;
                })
                .then(Mono.defer(() -> {
                    log.info("WebFilter 2 End");
                    return chain.filter(exchange);
                }));
        };
    }

    /*
     * WebFilter 3에서 예외를 발생시키고, 예외가 발생하면 에러 로그를 출력하고, BAD_REQUEST 상태 코드를 반환한다.
     * 예외가 발생하면 SecurityWebFilterChain의 다음 필터를 실행하지 않고, 예외 처리를 한다.
     */
    WebFilter customWebFilter3() {
        return new WebFilter() {
            @NonNull
            @Override
            public Mono<Void> filter(@NonNull ServerWebExchange exchange,
                @NonNull WebFilterChain chain) {
                return something()
                    .then(Mono.defer(() -> chain.filter(exchange)))
                    .onErrorResume(IllegalArgumentException.class, e -> {
                        log.error("error test");
                        ServerHttpResponse response = exchange.getResponse();
                        response.setStatusCode(HttpStatus.BAD_REQUEST);
                        return response.setComplete();
                    });
            }

            private Mono<Void> something() {
                return Mono.error(new IllegalArgumentException("Not implemented"));
            }
        };
    }

}
