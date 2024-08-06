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
package org.smartdata.server.config;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.SmartEngine;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

@RequiredArgsConstructor
public class SsmContextInitializer implements
    ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final SmartEngine smartEngine;

    private final SmartConf conf;

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
      ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();
      beanFactory.registerSingleton("smartConfig", conf);
      beanFactory.registerSingleton("smartEngine", smartEngine);
      beanFactory.registerSingleton("statesManager", smartEngine.getStatesManager());
      beanFactory.registerSingleton("cmdletManager", smartEngine.getCmdletManager());
      beanFactory.registerSingleton("ruleManager", smartEngine.getRuleManager());
      beanFactory.registerSingleton("auditService", smartEngine.getAuditService());
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
      beanFactory.registerSingleton("accessCountTableManager",
          smartEngine.getStatesManager().getAccessCountTableManager());
    }
}
