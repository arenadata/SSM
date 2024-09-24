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
package org.smartdata.agent.http;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.smartdata.http.SmartHttpServer;
import org.smartdata.metrics.MetricsFactory;
import org.smartdata.security.SmartPrincipalManager;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_HTTP_SERVER_PORT_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_HTTP_SERVER_PORT_KEY;

public class SmartAgentHttpServer extends SmartHttpServer {
  public static final String AGENT_PROFILE = "agent";

  public SmartAgentHttpServer(SmartConf ssmConfig, MetricsFactory metricsFactory) {
    super(ssmConfig, new ContextInitializer(metricsFactory), getServerPort(ssmConfig));
  }

  @RequiredArgsConstructor
  private static class ContextInitializer implements
      ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final MetricsFactory metricsFactory;

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
      ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();
      beanFactory.registerSingleton("metricsFactory", metricsFactory);
      beanFactory.registerSingleton("smartPrincipalManager",
          SmartPrincipalManager.noOp());
    }
  }

  @Override
  protected SpringApplicationBuilder customizeSpringApplication(SpringApplicationBuilder builder) {
    return builder.profiles(AGENT_PROFILE);
  }

  private static int getServerPort(SmartConf conf) {
    return conf.getInt(
        SMART_AGENT_HTTP_SERVER_PORT_KEY,
        SMART_AGENT_HTTP_SERVER_PORT_DEFAULT);
  }
}
