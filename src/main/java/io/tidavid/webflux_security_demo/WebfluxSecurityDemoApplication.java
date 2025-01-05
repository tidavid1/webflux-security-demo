package io.tidavid.webflux_security_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class WebfluxSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebfluxSecurityDemoApplication.class, args);
    }


    @RestController
    @RequestMapping("/api/v1/hello")
    public static class HelloController {

        @GetMapping
        public String hello() {
            return "Hello, World!";
        }
    }
}
