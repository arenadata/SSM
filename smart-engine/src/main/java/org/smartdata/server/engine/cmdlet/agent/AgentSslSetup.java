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
package org.smartdata.server.engine.cmdlet.agent;

import akka.actor.setup.Setup;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

/**
 * Key and trust managers of the Server-Agent communication, used by
 * {@link SmartSslEngineProvider}. They are passed to the actor system as a setup
 * instead of the Akka config, so that the key store passwords never get into
 * the config, which can be logged, e.g. with {@code akka.log-config-on-start}.
 */
public class AgentSslSetup extends Setup {
  private final KeyManager[] keyManagers;
  private final TrustManager[] trustManagers;

  public AgentSslSetup(KeyManager[] keyManagers, TrustManager[] trustManagers) {
    this.keyManagers = keyManagers;
    this.trustManagers = trustManagers;
  }

  public KeyManager[] getKeyManagers() {
    return keyManagers;
  }

  public TrustManager[] getTrustManagers() {
    return trustManagers;
  }
}
