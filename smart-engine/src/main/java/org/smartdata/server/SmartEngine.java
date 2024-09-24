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

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.AbstractService;
import org.smartdata.conf.SmartConf;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.cluster.ClusterNodesManager;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.StatesManager;
import org.smartdata.server.engine.audit.AuditService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SmartEngine extends AbstractService {
  public static final Logger LOG = LoggerFactory.getLogger(SmartEngine.class);

  private final SmartConf conf;
  @Getter
  private final ServerContext serverContext;
  @Getter
  private StatesManager statesManager;
  @Getter
  private RuleManager ruleManager;
  @Getter
  private CmdletManager cmdletManager;
  @Getter
  private AuditService auditService;
  @Getter
  private ClusterNodesManager clusterNodesManager;
  @Getter
  private SmartPrincipalManager smartPrincipalManager;
  private final List<AbstractService> services;

  public SmartEngine(ServerContext context) {
    super(context);
    this.serverContext = context;
    this.conf = serverContext.getConf();
    this.services = new ArrayList<>();
  }

  @Override
  public void init() throws IOException {
    statesManager = new StatesManager(serverContext);
    smartPrincipalManager = new ThreadScopeSmartPrincipalManager(
        new AnonymousDefaultPrincipalProvider());
    services.add(statesManager);
    auditService = new AuditService(serverContext.getMetaStore().userActivityDao());
    cmdletManager = new CmdletManager(serverContext, auditService, smartPrincipalManager);
    services.add(cmdletManager);
    clusterNodesManager = new ClusterNodesManager(conf, cmdletManager);
    ruleManager = new RuleManager(
        serverContext, statesManager, cmdletManager, auditService, smartPrincipalManager);
    services.add(ruleManager);

    for (AbstractService s : services) {
      s.init();
    }
  }

  @Override
  public boolean inSafeMode() {
    if (services.isEmpty()) { //Not initiated
      return true;
    }
    for (AbstractService service : services) {
      if (service.inSafeMode()) {
        return true;
      }
    }
    return false;
  }

  @Override
  public void start() throws IOException {
    for (AbstractService s : services) {
      s.start();
    }
  }

  @Override
  public void stop() throws IOException {
    for (int i = services.size() - 1; i >= 0; i--) {
      stopEngineService(services.get(i));
    }
  }

  private void stopEngineService(AbstractService service) {
    try {
      if (service != null) {
        service.stop();
      }
    } catch (IOException e) {
      LOG.error("Error while stopping {}", service.getClass().getCanonicalName(), e);
    }
  }

  public SmartConf getConf() {
    return serverContext.getConf();
  }
}
