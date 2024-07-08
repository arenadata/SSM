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

import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.SsmContextInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.solr.SolrHealthContributorAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.hazelcast.HazelcastAutoConfiguration;
import org.springframework.boot.autoconfigure.web.embedded.EmbeddedWebServerFactoryCustomizerAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.smartdata.conf.SmartConfKeys.SMART_CONF_KEYS_PREFIX;

public class SmartRestServer {
  private final SpringApplication springApplication;

  private volatile ConfigurableApplicationContext applicationContext;

  public SmartRestServer(SmartConf ssmConfig, SmartEngine smartEngine) {
    this.springApplication = new SpringApplication(RestServerApplication.class);

    injectToSpringProperties(ssmConfig);

    SsmContextInitializer contextInitializer =
        new SsmContextInitializer(smartEngine, ssmConfig);
    springApplication.addInitializers(contextInitializer);
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

  private boolean isRunning() {
    return applicationContext != null;
  }

  private void injectToSpringProperties(SmartConf ssmConfig) {
    Map<String, Object> ssmSpringProperties = new HashMap<>(
        // we want to save only SSM-related options
        ssmConfig.asMap(key -> key.startsWith(SMART_CONF_KEYS_PREFIX)));
    springApplication.setDefaultProperties(ssmSpringProperties);
  }

  @SpringBootApplication(exclude = {
      // todo remove exclusion after zeppelin removal
      EmbeddedWebServerFactoryCustomizerAutoConfiguration.class,
      // it's needed to prevent auto-registration of spring hazelcast node
      // in the SSM hazelcast workers cluster
      HazelcastAutoConfiguration.class,
      SolrHealthContributorAutoConfiguration.class
  })
  public static class RestServerApplication {
    // empty class just to enable auto configs
  }
}
