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
package org.smartdata.http;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.hazelcast.HazelcastAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.smartdata.conf.SmartConfKeys.SMART_CONF_KEYS_PREFIX;

public class SmartHttpServer {
  public static final String SERVER_PORT_QUALIFIER = "ssmHttpServerPort";

  private final SpringApplication springApplication;

  private volatile ConfigurableApplicationContext applicationContext;

  public SmartHttpServer(
      SmartConf ssmConfig,
      ApplicationContextInitializer<?> contextInitializer,
      int serverPort,
      Class<?>... sources) {
    SpringApplicationBuilder applicationBuilder = new SpringApplicationBuilder(
        RestServerApplication.class)
        .sources(sources)
        .initializers(new BaseContextInitializer(ssmConfig, serverPort), contextInitializer)
        .properties(getSsmProperties(ssmConfig))
        .profiles();

    this.springApplication = customizeSpringApplication(applicationBuilder).build();
  }

  public void start() {
    applicationContext = springApplication.run();
  }

  public void stop() {
    if (isRunning()) {
      SpringApplication.exit(applicationContext);
      applicationContext = null;
    }
  }

  protected SpringApplicationBuilder customizeSpringApplication(
      SpringApplicationBuilder builder) {
    return builder;
  }

  private boolean isRunning() {
    return applicationContext != null;
  }

  private Map<String, Object> getSsmProperties(SmartConf ssmConfig) {
    return new HashMap<>(
        // we want to save only SSM-related options
        ssmConfig.asMap(key -> key.startsWith(SMART_CONF_KEYS_PREFIX)));
  }

  @RequiredArgsConstructor
  private static class BaseContextInitializer implements
      ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final SmartConf conf;
    private final int serverPort;

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
      ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();
      beanFactory.registerSingleton(SERVER_PORT_QUALIFIER, serverPort);
      beanFactory.registerSingleton("smartConfig", conf);
    }
  }

  @SpringBootApplication(exclude = {
      // it's needed to prevent auto-registration of spring hazelcast node
      // in the SSM hazelcast workers cluster
      HazelcastAutoConfiguration.class,
      // we configure metrics registry by ourselves in
      // MetricsFactory#from(SmartConf) before Spring context initialization
      MetricsAutoConfiguration.class
  })
  public static class RestServerApplication {
    // empty class just to enable auto configs
  }
}
