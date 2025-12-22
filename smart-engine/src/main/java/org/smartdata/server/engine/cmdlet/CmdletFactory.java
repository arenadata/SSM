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
import org.smartdata.SmartContext;
import org.smartdata.action.ActionException;
import org.smartdata.action.ActionRegistry;
import org.smartdata.action.CmdletFactoryPlugin;
import org.smartdata.action.SmartAction;
import org.smartdata.hdfs.action.HdfsCmdletFactoryPlugin;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;
import org.smartdata.hive.action.HmsCmdletFactoryPlugin;
import org.smartdata.model.LaunchAction;
import org.smartdata.ozone.action.OzoneCmdletFactoryPlugin;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class CmdletFactory implements Closeable {
  private final SmartContext smartContext;
  private final UserImpersonationStrategy userImpersonationStrategy;
  private final List<CmdletFactoryPlugin> plugins;
  private final ActionRegistry actionRegistry;

  public CmdletFactory(SmartContext smartContext,
      UserImpersonationStrategy userImpersonationStrategy,
      ActionRegistry actionRegistry) {
    this(smartContext,
        userImpersonationStrategy,
        actionRegistry,
        new HdfsCmdletFactoryPlugin(smartContext.getConf(), userImpersonationStrategy),
        new HmsCmdletFactoryPlugin(smartContext.getConf(), userImpersonationStrategy),
        new OzoneCmdletFactoryPlugin(smartContext.getConf(), userImpersonationStrategy)
    );
  }

  public CmdletFactory(SmartContext smartContext,
      UserImpersonationStrategy userImpersonationStrategy,
      ActionRegistry actionRegistry,
      CmdletFactoryPlugin... plugins) {
    this.smartContext = smartContext;
    this.actionRegistry = actionRegistry;
    this.userImpersonationStrategy = userImpersonationStrategy;
    this.plugins = Arrays.asList(plugins);
  }

  public Cmdlet createCmdlet(LaunchCmdlet launchCmdlet) throws ActionException {
    List<SmartAction> actions = new ArrayList<>();
    int idx = 0;
    for (LaunchAction launchAction : launchCmdlet.getLaunchActions()) {
      idx++;
      SmartAction action = createAction(
          launchCmdlet.getCmdletId(),
          idx == launchCmdlet.getLaunchActions().size(),
          launchAction,
          userImpersonationStrategy.getUserFor(launchCmdlet));
      actions.add(action);
    }
    return Cmdlet.builder()
        .id(launchCmdlet.getCmdletId())
        .actions(actions)
        .owner(launchCmdlet.getOwner())
        .build();
  }

  public SmartAction createAction(
      long cmdletId,
      boolean isLastAction,
      LaunchAction launchAction,
      String actionUser) throws ActionException {
    SmartAction smartAction = actionRegistry.createAction(launchAction.getActionType());
    smartAction.setContext(smartContext);
    smartAction.setCmdletId(cmdletId);
    smartAction.setLastAction(isLastAction);
    smartAction.init(launchAction.getArgs());
    smartAction.setActionId(launchAction.getActionId());
    enrichAction(smartAction, actionUser);
    return smartAction;
  }

  private void enrichAction(SmartAction action, String actionUser) throws ActionException {
    for (CmdletFactoryPlugin plugin : plugins) {
      if (!plugin.canEnrich(action)) {
        continue;
      }
      plugin.enrichAction(action, actionUser);
    }
  }

  @Override
  public void close() {
    Exception exception = null;
    for (CmdletFactoryPlugin plugin : plugins) {
      try {
        plugin.close();
      } catch (IOException exc) {
        String errorMessage = "Error closing cmdlet factory plugin";
        log.error(errorMessage, exc);
        exception = exc;
      }
    }

    if (exception != null) {
      throw new RuntimeException(exception);
    }
  }
}
