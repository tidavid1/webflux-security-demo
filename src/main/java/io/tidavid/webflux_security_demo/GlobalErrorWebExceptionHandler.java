package io.tidavid.webflux_security_demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class GlobalErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalErrorWebExceptionHandler.class);

    @Override
    @NonNull
    public Mono<Void> handle(@NonNull ServerWebExchange exchange, @NonNull Throwable ex) {
        // 여기서 예외를 로깅하거나 상태코드 및 응답 바디를 세팅
        ServerHttpResponse response = exchange.getResponse();
        log.error("GlobalErrorWebExceptionHandler: exception raise", ex);
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().add("Content-Type", "text/plain");
        return response.writeWith(
            Mono.just(response.bufferFactory().wrap(ex.getMessage().getBytes())));
    }
}
