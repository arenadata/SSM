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
package org.smartdata.integration.auth;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import org.smartdata.integration.IntegrationTestBase;
import org.springframework.util.Assert;

public class InMemoryLdapServer {
  private final InMemoryDirectoryServer directoryServer;

  private InMemoryLdapServer(InMemoryDirectoryServer directoryServer) {
    this.directoryServer = directoryServer;
  }

  public void start() throws LDAPException {
    directoryServer.startListening();
  }

  public void stop() {
    directoryServer.shutDown(true);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String baseDn;
    private String bindDn;
    private String bindPassword;
    private String ldifResourcePath;
    private boolean enableValidation;
    private int port;

    public Builder baseDn(String baseDn) {
      this.baseDn = baseDn;
      return this;
    }

    public Builder bindDn(String bindDn) {
      this.bindDn = bindDn;
      return this;
    }

    public Builder bindPassword(String bindPassword) {
      this.bindPassword = bindPassword;
      return this;
    }

    public Builder ldifResourcePath(String ldifResourcePath) {
      this.ldifResourcePath = ldifResourcePath;
      return this;
    }

    public Builder port(int port) {
      this.port = port;
      return this;
    }

    public Builder enableValidation() {
      this.enableValidation = true;
      return this;
    }

    public InMemoryLdapServer build() throws LDAPException {
      Assert.notNull(baseDn, "baseDn not provided");
      InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(baseDn);
      if (bindDn != null && bindPassword != null) {
        config.addAdditionalBindCredentials(bindDn, bindPassword);
      }
      if (!enableValidation) {
        config.setSchema(null);
      }
      config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP", port));

      InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
      directoryServer.importFromLDIF(false, IntegrationTestBase.resourceAbsolutePath(ldifResourcePath));

      return new InMemoryLdapServer(directoryServer);
    }
  }
}
