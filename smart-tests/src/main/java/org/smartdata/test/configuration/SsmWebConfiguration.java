package org.smartdata.test.configuration;


import io.arenadata.test.model.UserModel;
import io.arenadata.test.model.UserRole;
import io.arenadata.test.service.UserProvider;
import io.arenadata.test.service.impl.UserProviderImpl;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "ssm-web")
@Setter
public class SsmWebConfiguration {
    private List<UserModel<UserRole>> credentials;

    @Bean
    public List<UserModel<UserRole>> testCredentials() {
        return credentials;
    }

    @Bean
    public UserProvider<UserRole> ssmUserProvider() {
        return new UserProviderImpl(credentials);
    }
}
