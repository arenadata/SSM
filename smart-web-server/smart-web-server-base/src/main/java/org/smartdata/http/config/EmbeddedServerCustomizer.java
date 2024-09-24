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
package org.smartdata.http.config;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static org.smartdata.http.SmartHttpServer.SERVER_PORT_QUALIFIER;
import static org.smartdata.http.config.ConfigKeys.SSL_ENABLED;
import static org.smartdata.http.config.ConfigKeys.SSL_ENABLED_DEFAULT;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PASSWORD;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PATH;
import static org.smartdata.http.config.ConfigKeys.SSL_KEY_ALIAS;
import static org.smartdata.http.config.ConfigKeys.SSL_KEY_PASSWORD;

@Component
@RequiredArgsConstructor
public class EmbeddedServerCustomizer
    implements WebServerFactoryCustomizer<ConfigurableWebServerFactory> {

  private final SmartConf conf;

  @Qualifier(SERVER_PORT_QUALIFIER)
  private final int serverPort;

  @Override
  public void customize(ConfigurableWebServerFactory factory) {
    factory.setPort(serverPort);
    getSslConfig().ifPresent(factory::setSsl);
  }

  private Optional<Ssl> getSslConfig() {
    if (!conf.getBoolean(SSL_ENABLED, SSL_ENABLED_DEFAULT)) {
      return Optional.empty();
    }

    Ssl sslConfig = new Ssl();
    sslConfig.setEnabled(true);
    sslConfig.setKeyStore(conf.getNonEmpty(SSL_KEYSTORE_PATH));
    sslConfig.setKeyStorePassword(conf.getNonEmpty(SSL_KEYSTORE_PASSWORD));
    sslConfig.setKeyAlias(conf.get(SSL_KEY_ALIAS));
    sslConfig.setKeyPassword(conf.get(SSL_KEY_PASSWORD));
    return Optional.of(sslConfig);
  }
}
