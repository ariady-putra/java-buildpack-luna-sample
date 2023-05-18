package io.pivotal.luna;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class SecurityProvidersController {

    @GetMapping("/security-providers")
    List<ProviderProjection> securityProviders() {
        return Arrays
                .stream(Security.getProviders())
                .map(ProviderProjection::new)
                .collect(Collectors.toList());
    }

    static final class ProviderProjection {

        private final Provider provider;

        private ProviderProjection(Provider provider) {
            this.provider = provider;
        }

        public String getInfo() {
            return this.provider.getInfo();
        }

        public String getName() {
            return this.provider.getName();
        }

        public double getVersion() {
            return this.provider.getVersion();
        }

    }
}
