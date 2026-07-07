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

import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.smartdata.conf.SmartConf;
import org.springframework.boot.web.server.Compression;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.Http2;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.SslStoreProvider;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.smartdata.http.config.ConfigKeys.SSL_ENABLED;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PASSWORD;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PATH;

/**
 * Tests SSL settings prepared by EmbeddedServerCustomizer.
 */
public class EmbeddedServerCustomizerTest {

  private static final int SERVER_PORT = 8081;
  private static final String KEYSTORE_PATH = "classpath:ssl/keystore.jks";
  private static final String KEYSTORE_PASSWORD = "keystore_password";

  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  @Test
  public void useCredentialProviderForKeystorePassword() throws Exception {
    SmartConf conf = createSslConf();
    String providerPath = createCredentialProvider(SSL_KEYSTORE_PASSWORD, KEYSTORE_PASSWORD);
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, providerPath);

    CapturingWebServerFactory factory = customize(conf);

    assertEquals(KEYSTORE_PASSWORD, factory.ssl.getKeyStorePassword());
  }

  @Test
  public void usePlainConfigFallbackForKeystorePassword() {
    SmartConf conf = createSslConf();
    conf.set(SSL_KEYSTORE_PASSWORD, KEYSTORE_PASSWORD);

    CapturingWebServerFactory factory = customize(conf);

    assertEquals(KEYSTORE_PASSWORD, factory.ssl.getKeyStorePassword());
  }

  @Test
  public void failWhenKeystorePasswordIsMissing() {
    SmartConf conf = createSslConf();

    assertRequiredOptionError(conf);
  }

  @Test
  public void failWhenKeystorePasswordIsBlank() {
    SmartConf conf = createSslConf();
    conf.set(SSL_KEYSTORE_PASSWORD, "  ");

    assertRequiredOptionError(conf);
  }

  private void assertRequiredOptionError(SmartConf conf) {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> customize(conf)
    );

    assertEquals(
        "Required option not provided: " + SSL_KEYSTORE_PASSWORD,
        exception.getMessage());
  }

  private SmartConf createSslConf() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, KEYSTORE_PATH);
    return conf;
  }

  private CapturingWebServerFactory customize(SmartConf conf) {
    EmbeddedServerCustomizer customizer = new EmbeddedServerCustomizer(conf, SERVER_PORT);
    CapturingWebServerFactory factory = new CapturingWebServerFactory();
    customizer.customize(factory);
    return factory;
  }

  private String createCredentialProvider(String alias, String password) throws Exception {
    File credentialFile = new File(temporaryFolder.newFolder(), "ssl.jceks");
    String providerPath = new URI(
        "jceks",
        "file",
        credentialFile.toURI().getPath(),
        null
    ).toString();
    SmartConf conf = new SmartConf();
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, providerPath);

    CredentialProvider provider = CredentialProviderFactory.getProviders(conf).get(0);
    provider.createCredentialEntry(alias, password.toCharArray());
    provider.flush();
    return providerPath;
  }

  private static class CapturingWebServerFactory implements ConfigurableWebServerFactory {
    private Ssl ssl;

    @Override
    public void setPort(int port) {
    }

    @Override
    public void setAddress(InetAddress address) {
    }

    @Override
    public void setErrorPages(Set<? extends ErrorPage> errorPages) {
    }

    @Override
    public void setSsl(Ssl ssl) {
      this.ssl = ssl;
    }

    @Override
    public void setSslStoreProvider(SslStoreProvider sslStoreProvider) {
    }

    @Override
    public void setHttp2(Http2 http2) {
    }

    @Override
    public void setCompression(Compression compression) {
    }

    @Override
    public void setServerHeader(String serverHeader) {
    }

    @Override
    public void addErrorPages(ErrorPage... errorPages) {
    }
  }
}
