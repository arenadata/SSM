/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.test.configuration;

import io.arenadata.test.configuration.CommonTestConfiguration;
import io.arenadata.test.model.Component;
import io.arenadata.test.service.HostService;
import io.arenadata.test.service.SshCommandExecutor;
import io.arenadata.test.service.impl.DockerComposeService;
import io.arenadata.test.service.impl.RemoteHostService;
import lombok.Getter;
import lombok.Setter;
import org.smartdata.test.model.SsmComponent;
import org.smartdata.test.service.SsmComponentConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Setter
@Getter
@Configuration
@EnableConfigurationProperties
@PropertySource("classpath:application.yaml")
@Import(CommonTestConfiguration.class)
public class SsmTestConfiguration {

    @Bean
    public List<Component> ssmComponents() {
        return Arrays.stream(SsmComponent.values()).map(c -> (Component) c).collect(Collectors.toList());
    }

    @Bean
    @ConfigurationPropertiesBinding
    public Converter<String, Component> ssmComponentConverter() {
        return new SsmComponentConverter();
    }

    @Bean("hostService")
    @ConfigurationProperties(prefix = "docker-compose-service")
    @ConditionalOnProperty(name = "env-type", havingValue = "docker")
    public HostService dockerHostService(List<Component> ssmComponents) {
        return new DockerComposeService(ssmComponents);
    }

    @Bean("hostService")
    @ConditionalOnProperty(name = "env-type", havingValue = "remote")
    public HostService remoteHostService(SshCommandExecutor sshCommandExecutor) {
        return new RemoteHostService(sshCommandExecutor);
    }
}
