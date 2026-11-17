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

import akka.actor.ActorSystem;
import akka.remote.transport.netty.ConfigSSLEngineProvider;
import com.typesafe.config.Config;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.util.Arrays;
import java.util.regex.Pattern;

import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_PEER_SUBJECT_PATTERN_KEY;

/**
 * SSL engine provider of the Akka classic remoting, which in addition to the trust store
 * validation checks the subject of the peer certificate. Since the Server and Agent
 * certificates are usually issued by the same CA, this check prevents an Agent
 * from impersonating the Server and vice versa.
 *
 * <p>Instantiated by Akka via reflection, see {@code akka.remote.netty.ssl.ssl-engine-provider}.
 */
public class SmartSslEngineProvider extends ConfigSSLEngineProvider {

  private final Pattern peerSubjectPattern;

  public SmartSslEngineProvider(ActorSystem system) {
    super(system);
    // the SSL context is created lazily, so this field is initialized
    // before the first trustManagers() call
    Config config = system.settings().config();
    // set only if the subject check is enabled
    this.peerSubjectPattern = config.hasPath(AKKA_SSL_PEER_SUBJECT_PATTERN_KEY)
        ? Pattern.compile(config.getString(AKKA_SSL_PEER_SUBJECT_PATTERN_KEY))
        : null;
  }

  @Override
  public TrustManager[] trustManagers() {
    TrustManager[] trustManagers = super.trustManagers();
    if (peerSubjectPattern == null) {
      return trustManagers;
    }
    return Arrays.stream(trustManagers)
        .map(this::withSubjectCheck)
        .toArray(TrustManager[]::new);
  }

  private TrustManager withSubjectCheck(TrustManager trustManager) {
    return trustManager instanceof X509TrustManager
        ? new PeerSubjectTrustManager((X509TrustManager) trustManager, peerSubjectPattern)
        : trustManager;
  }
}
