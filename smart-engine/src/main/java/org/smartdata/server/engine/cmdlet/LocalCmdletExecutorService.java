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
package org.smartdata.server.engine.cmdlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.action.ActionException;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.ExecutorType;
import org.smartdata.protocol.message.LaunchCmdlet;
import org.smartdata.protocol.message.StatusMessage;
import org.smartdata.protocol.message.StatusReporter;
import org.smartdata.server.cluster.NodeInfo;
import org.smartdata.server.engine.ActiveServerInfo;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.EngineEventBus;
import org.smartdata.server.engine.message.AddNodeMessage;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class LocalCmdletExecutorService extends CmdletExecutorService implements StatusReporter {
  private static final Logger LOG = LoggerFactory.getLogger(LocalCmdletExecutorService.class);

  private final SmartConf conf;
  private final boolean disableLocalExec;
  private CmdletFactory cmdletFactory;
  private CmdletExecutor cmdletExecutor;
  private ScheduledExecutorService executorService;

  public LocalCmdletExecutorService(SmartConf smartConf, CmdletManager cmdletManager) {
    super(cmdletManager, ExecutorType.LOCAL);
    this.conf = smartConf;
    // If local executor is disabled, there is no need to execute the remain code in the
    // instantiation.
    this.disableLocalExec = conf.getBoolean(
        SmartConfKeys.SMART_ACTION_LOCAL_EXECUTION_DISABLED_KEY,
        SmartConfKeys.SMART_ACTION_LOCAL_EXECUTION_DISABLED_DEFAULT);
    if (disableLocalExec) {
      return;
    }

    this.cmdletFactory = new CmdletFactory(cmdletManager.getContext());
    this.cmdletExecutor = new CmdletExecutor(smartConf);
    this.executorService = Executors.newSingleThreadScheduledExecutor();
  }

  @Override
  public void start() {
    ActiveServerInfo.setInstance(getActiveServerAddress());
    EngineEventBus.post(new AddNodeMessage(ActiveServerInfo.getInstance()));

    if (disableLocalExec) {
      return;
    }
    int reportPeriod = conf.getInt(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_DEFAULT);
    StatusReportTask statusReportTask = new StatusReportTask(this, cmdletExecutor, conf);
    this.executorService.scheduleAtFixedRate(
        statusReportTask, 1000, reportPeriod, TimeUnit.MILLISECONDS);
  }

  @Override
  public boolean canAcceptMore() {
    return true;
  }

  public int getNumNodes() {
    return 1;
  }

  public List<NodeInfo> getNodesInfo() {
    // TODO: to be refined
    List<NodeInfo> ret = new ArrayList<>(1);
    ret.add(ActiveServerInfo.getInstance());
    return ret;
  }

  @Override
  public String execute(LaunchCmdlet cmdlet) {
    try {
      this.cmdletExecutor.execute(cmdletFactory.createCmdlet(cmdlet));
      return ActiveServerInfo.getInstance().getId();
    } catch (ActionException e) {
      LOG.error("Failed to execute cmdlet {}" , cmdlet.getCmdletId(), e);
      return null;
    }
  }

  @Override
  public void stop(long cmdletId) {
    cmdletExecutor.stop(cmdletId);
  }

  @Override
  public void shutdown() {
    executorService.shutdown();
    cmdletExecutor.shutdown();
    cmdletFactory.close();
  }

  @Override
  public void report(StatusMessage status) {
    LOG.debug("Reporting status message " + status);
    cmdletManager.updateStatus(status);
  }

  private String getActiveServerAddress() {
    String srv = conf.get(SmartConfKeys.SMART_AGENT_MASTER_ADDRESS_KEY);
    if (srv == null || srv.isEmpty()) {
      try {
        srv = InetAddress.getLocalHost().getHostName();
      } catch (UnknownHostException e) {
        srv = "127.0.0.1";
      }
    }
    return srv;
  }
}
