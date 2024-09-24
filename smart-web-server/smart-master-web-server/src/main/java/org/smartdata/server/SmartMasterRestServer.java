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
package org.smartdata.server;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.smartdata.http.SmartHttpServer;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ComponentScan;

import static org.smartdata.conf.SmartConfKeys.SMART_REST_SERVER_PORT_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_REST_SERVER_PORT_KEY_DEFAULT;

public class SmartMasterRestServer extends SmartHttpServer {
  public static final String SSM_MASTER_PROFILE = "master";

  public SmartMasterRestServer(SmartConf ssmConfig, SmartEngine smartEngine) {
    super(ssmConfig, new ContextInitializer(smartEngine),
        getServerPort(ssmConfig), EnableComponentScan.class);
  }

  @RequiredArgsConstructor
  private static class ContextInitializer implements
      ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final SmartEngine smartEngine;

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
      ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();
      beanFactory.registerSingleton("smartEngine", smartEngine);
      beanFactory.registerSingleton("statesManager", smartEngine.getStatesManager());
      beanFactory.registerSingleton("cmdletManager", smartEngine.getCmdletManager());
      beanFactory.registerSingleton("ruleManager", smartEngine.getRuleManager());
      beanFactory.registerSingleton("auditService", smartEngine.getAuditService());
      beanFactory.registerSingleton("metricsFactory",
          smartEngine.getServerContext().getMetricsFactory());
      beanFactory.registerSingleton("clusterNodesManager",
          smartEngine.getClusterNodesManager());
      beanFactory.registerSingleton(
          "cmdletInfoHandler", smartEngine.getCmdletManager().getCmdletInfoHandler());
      beanFactory.registerSingleton(
          "actionInfoHandler", smartEngine.getCmdletManager().getActionInfoHandler());
      beanFactory.registerSingleton(
          "cachedFilesManager", smartEngine.getStatesManager().getCachedFilesManager());
      beanFactory.registerSingleton(
          "smartPrincipalManager", smartEngine.getSmartPrincipalManager());
      beanFactory.registerSingleton("dbFileAccessManager",
          smartEngine.getStatesManager().getFileAccessManager());
    }
  }

  @Override
  protected SpringApplicationBuilder customizeSpringApplication(SpringApplicationBuilder builder) {
    return builder.profiles(SSM_MASTER_PROFILE);
  }

  private static int getServerPort(SmartConf conf) {
    return conf.getInt(SMART_REST_SERVER_PORT_KEY, SMART_REST_SERVER_PORT_KEY_DEFAULT);
  }

  @ComponentScan(basePackages = "org.smartdata.server")
  public static class EnableComponentScan {
  }
}
