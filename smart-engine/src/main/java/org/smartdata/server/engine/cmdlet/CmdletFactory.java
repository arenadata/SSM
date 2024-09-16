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

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.SmartContext;
import org.smartdata.action.ActionException;
import org.smartdata.action.ActionRegistry;
import org.smartdata.action.SmartAction;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.hdfs.client.CachingDfsClientProvider;
import org.smartdata.hdfs.client.DfsClientProvider;
import org.smartdata.model.LaunchAction;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class CmdletFactory implements Closeable {
  static final Logger LOG = LoggerFactory.getLogger(CmdletFactory.class);

  private final SmartContext smartContext;
  private final DfsClientProvider dfsClientProvider;

  public CmdletFactory(SmartContext smartContext) {
    this(smartContext, new CachingDfsClientProvider(smartContext.getConf()));
  }

  public CmdletFactory(SmartContext smartContext, DfsClientProvider dfsClientProvider) {
    this.smartContext = smartContext;
    this.dfsClientProvider = dfsClientProvider;
  }

  public Cmdlet createCmdlet(LaunchCmdlet launchCmdlet) throws ActionException {
    List<SmartAction> actions = new ArrayList<>();
    int idx = 0;
    for (LaunchAction action : launchCmdlet.getLaunchActions()) {
      idx++;
      actions.add(createAction(launchCmdlet.getCmdletId(),
          idx == launchCmdlet.getLaunchActions().size(), action));
    }
    Cmdlet cmdlet = new Cmdlet(actions);
    cmdlet.setId(launchCmdlet.getCmdletId());
    return cmdlet;
  }

  public SmartAction createAction(long cmdletId, boolean isLastAction, LaunchAction launchAction)
      throws ActionException {
    SmartAction smartAction = ActionRegistry.createAction(launchAction.getActionType());
    smartAction.setContext(smartContext);
    smartAction.setCmdletId(cmdletId);
    smartAction.setLastAction(isLastAction);
    smartAction.init(launchAction.getArgs());
    smartAction.setActionId(launchAction.getActionId());
    if (smartAction instanceof HdfsAction) {
      setDfsClient((HdfsAction) smartAction);
    }
    return smartAction;
  }

  private void setDfsClient(HdfsAction action) throws ActionException {
    try {
      action.setDfsClient(
          dfsClientProvider.provide(smartContext.getConf(), action.dfsClientType())
      );
    } catch (IOException exception) {
      LOG.error("smartAction aid={} setDfsClient error", action.getActionId(), exception);
      throw new ActionException(exception);
    }
  }

  @Override
  public void close() {
    try {
      dfsClientProvider.close();
    } catch (IOException exception) {
      String errorMessage = "Error closing DFS client provider";
      log.error(errorMessage, exception);
      throw new RuntimeException(errorMessage, exception);
    }
  }
}
