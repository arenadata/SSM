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

import akka.actor.BootstrapSetup;
import akka.actor.setup.ActorSystemSetup;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigValueFactory;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_KEYSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_KEYSTORE_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_KEY_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_KEYSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_KEYSTORE_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_KEY_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_TRUSTSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_TRUSTSTORE_PASSWORD_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_ENABLED_TRANSPORTS_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_ENGINE_PROVIDER_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_SECURITY_PREFIX;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_TRANSPORT;

/**
 * Applies the SSL/TLS settings of the Server-Agent communication from {@link SmartConf}
 * to the actor system setup. When SSL is enabled, only the TLS transport with mutual
 * authentication is enabled, so plaintext connections are rejected.
 *
 * <p>The key and trust managers are created here and passed with {@link AgentSslSetup},
 * so the key store passwords never get into the Akka config.
 */
public class AgentSslConfig {
  private static final Logger LOG = LoggerFactory.getLogger(AgentSslConfig.class);

  /** The side of the Server-Agent communication the Akka config is built for. */
  public enum Role {
    SERVER(SMART_AGENT_SSL_SERVER_KEYSTORE_KEY,
        SMART_AGENT_SSL_SERVER_KEYSTORE_PASSWORD_KEY,
        SMART_AGENT_SSL_SERVER_KEY_PASSWORD_KEY,
        SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY),
    AGENT(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY,
        SMART_AGENT_SSL_AGENT_KEYSTORE_PASSWORD_KEY,
        SMART_AGENT_SSL_AGENT_KEY_PASSWORD_KEY,
        SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY);

    private final String keyStoreKey;
    private final String keyStorePasswordKey;
    private final String keyPasswordKey;
    /** Pattern the certificate of the opposite side must match. */
    private final String peerSubjectPatternKey;

    Role(String keyStoreKey, String keyStorePasswordKey,
        String keyPasswordKey, String peerSubjectPatternKey) {
      this.keyStoreKey = keyStoreKey;
      this.keyStorePasswordKey = keyStorePasswordKey;
      this.keyPasswordKey = keyPasswordKey;
      this.peerSubjectPatternKey = peerSubjectPatternKey;
    }
  }

  public static boolean isEnabled(SmartConf conf) {
    return conf.getBoolean(SMART_AGENT_SSL_ENABLED_KEY, SMART_AGENT_SSL_ENABLED_DEFAULT);
  }

  public static ActorSystemSetup apply(
      Config config, SmartConf conf, Role role) throws IOException {
    if (!isEnabled(conf)) {
      return ActorSystemSetup.create(BootstrapSetup.create(config));
    }

    Config sslConfig = config
        .withValue(AKKA_ENABLED_TRANSPORTS_KEY,
            ConfigValueFactory.fromIterable(Collections.singletonList(AKKA_SSL_TRANSPORT)))
        .withValue(AKKA_SSL_ENGINE_PROVIDER_KEY,
            ConfigValueFactory.fromAnyRef(SmartSslEngineProvider.class.getName()))
        .withValue(AKKA_SSL_SECURITY_PREFIX + "require-mutual-authentication",
            ConfigValueFactory.fromAnyRef(true));

    // created eagerly to fail fast on the invalid configuration
    // instead of failing on every association attempt
    AgentSslSetup sslSetup = new AgentSslSetup(
        createKeyManagers(conf, role), createTrustManagers(conf, role));
    return ActorSystemSetup.create(BootstrapSetup.create(sslConfig), sslSetup);
  }

  private static KeyManager[] createKeyManagers(
      SmartConf conf, Role role) throws IOException {
    String path = getRequired(conf, role.keyStoreKey);
    String keyStorePassword = getPassword(conf, role.keyStorePasswordKey)
        .orElseThrow(() -> missingOption(role.keyStorePasswordKey));
    String keyPassword = getPassword(conf, role.keyPasswordKey)
        .orElse(keyStorePassword);

    KeyStore keyStore = loadKeyStore(path, keyStorePassword, role.keyStoreKey);
    try {
      if (!containsKey(keyStore)) {
        throw new IOException("Key store " + path + " configured in option "
            + role.keyStoreKey + " doesn't contain a private key");
      }
      // fails if the key password doesn't unlock the private keys
      KeyManagerFactory factory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(keyStore, keyPassword.toCharArray());
      return factory.getKeyManagers();
    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to load the private key from key store " + path
          + ", check option " + role.keyPasswordKey + ": " + e.getMessage(), e);
    }
  }

  private static TrustManager[] createTrustManagers(
      SmartConf conf, Role role) throws IOException {
    String path = getRequired(conf, SMART_AGENT_SSL_TRUSTSTORE_KEY);
    String password = getPassword(conf, SMART_AGENT_SSL_TRUSTSTORE_PASSWORD_KEY)
        .orElse("");

    KeyStore trustStore = loadKeyStore(path, password, SMART_AGENT_SSL_TRUSTSTORE_KEY);
    TrustManager[] trustManagers;
    try {
      TrustManagerFactory factory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      factory.init(trustStore);
      trustManagers = factory.getTrustManagers();
    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to load trust store " + path + ": " + e.getMessage(), e);
    }

    if (!conf.getBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY,
        SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_DEFAULT)) {
      LOG.info("Peer certificate subject check is disabled, any peer certificate "
          + "trusted by the trust store will be accepted");
      return trustManagers;
    }

    // required, since otherwise an Agent could impersonate the Server
    // if their certificates are issued by the same CA
    Pattern peerSubjectPattern = getPattern(conf, role.peerSubjectPatternKey);
    return Arrays.stream(trustManagers)
        .map(trustManager -> trustManager instanceof X509TrustManager
            ? new PeerSubjectTrustManager((X509TrustManager) trustManager, peerSubjectPattern)
            : trustManager)
        .toArray(TrustManager[]::new);
  }

  private static Pattern getPattern(SmartConf conf, String key) throws IOException {
    String pattern = getRequired(conf, key);
    try {
      return Pattern.compile(pattern);
    } catch (PatternSyntaxException e) {
      throw new IOException("Invalid regular expression in option "
          + key + ": " + e.getMessage(), e);
    }
  }

  private static boolean containsKey(KeyStore keyStore) throws GeneralSecurityException {
    for (String alias : Collections.list(keyStore.aliases())) {
      if (keyStore.isKeyEntry(alias)) {
        return true;
      }
    }
    return false;
  }

  private static String getRequired(SmartConf conf, String key) throws IOException {
    String value = conf.getTrimmed(key);
    if (StringUtils.isBlank(value)) {
      throw missingOption(key);
    }
    return value;
  }

  private static Optional<String> getPassword(SmartConf conf, String key) throws IOException {
    return conf.getPasswordFromHadoop(key)
        .filter(StringUtils::isNotBlank);
  }

  private static IOException missingOption(String key) {
    return new IOException("Required option not provided: " + key);
  }

  private static KeyStore loadKeyStore(
      String path, String password, String optionKey) throws IOException {
    try {
      // detects the key store type, so both JKS and PKCS12 are supported
      return KeyStore.getInstance(new File(path), password.toCharArray());
    } catch (IOException | GeneralSecurityException e) {
      throw new IOException("Failed to load key store " + path
          + " configured in option " + optionKey + ": " + e.getMessage(), e);
    }
  }
}
