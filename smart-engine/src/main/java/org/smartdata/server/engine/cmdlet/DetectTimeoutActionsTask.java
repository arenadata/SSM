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
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.protocol.message.ActionStatus;
import org.smartdata.protocol.message.ActionStatusFactory;
import org.smartdata.server.engine.action.ActionStatusUpdateListener;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 Detects completed actions that exceed the specified execution time,
 tries to predict the result of execution (success or failure)
 and notifies the ActionStatusUpdateListener about it.
 */
public class DetectTimeoutActionsTask implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(DetectTimeoutActionsTask.class);
  public static final int TIMEOUT_MULTIPLIER = 100;
  public static final int TIMEOUT_MIN_MILLISECOND = 30000;

  private final Set<Long> cmdletsToLaunch;
  private final ActionStatusUpdateListener actionStatusUpdateListener;
  private final CmdletManagerContext context;
  private final long timeout;

  public DetectTimeoutActionsTask(
      CmdletManagerContext context,
      ActionStatusUpdateListener actionStatusUpdateListener,
      Set<Long> cmdletsToLaunch) {
    this.cmdletsToLaunch = cmdletsToLaunch;
    this.context = context;
    this.actionStatusUpdateListener = actionStatusUpdateListener;

    int reportPeriod = context.getConf().getInt(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_DEFAULT);
    // Max interval of status report, by default 500ms.
    int maxInterval = reportPeriod * context.getConf().getInt(
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_MULTIPLIER_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_MULTIPLIER_DEFAULT);
    // TIMEOUT_MULTIPLIER * maxInterval, 50s by default, is a potential timeout
    // value. And the least timeout value is 30s according to the below code.
    this.timeout = Math.max(TIMEOUT_MULTIPLIER * maxInterval, TIMEOUT_MIN_MILLISECOND);
  }

  public void run() {
    try {
      List<Long> cmdletIds = new ArrayList<>(cmdletsToLaunch);
      for (Long cmdletId : cmdletIds) {
        CmdletInfo cmdletInfo = context.getInMemoryRegistry().getUnfinishedCmdlet(cmdletId);
        if (cmdletInfo == null) {
          continue;
        }
        if (cmdletInfo.getState() == CmdletState.DISPATCHED
            || cmdletInfo.getState() == CmdletState.EXECUTING) {
          for (long id : cmdletInfo.getActionIds()) {
            ActionInfo actionInfo = context.getInMemoryRegistry().getUnfinishedAction(id);
            if (!isTimeout(actionInfo)) {
              continue;
            }
            // For timeout action, speculate its status and set result
            // if needed.
            ActionStatus actionStatus;
            if (isSuccessfulBySpeculation(actionInfo)) {
              actionStatus =
                  ActionStatusFactory.createSuccessActionStatus(
                      cmdletInfo, actionInfo);
            } else {
              actionStatus =
                  ActionStatusFactory.createTimeoutActionStatus(
                      cmdletInfo, actionInfo);
            }
            actionStatusUpdateListener.onStatusUpdate(actionStatus);
          }
        }
      }
    } catch (ActionException | IOException e) {
      LOG.error(e.getMessage());
    } catch (Exception t) {
      LOG.error("Unexpected exception occurs.", t);
    }
  }

  private boolean isTimeout(ActionInfo actionInfo) {
    if (actionInfo.isFinished() || actionInfo.getFinishTime() == 0) {
      return false;
    }
    long currentTime = System.currentTimeMillis();
    return currentTime - actionInfo.getFinishTime() > timeout;
  }

  private boolean isSuccessfulBySpeculation(ActionInfo actionInfo) {
    // If it is successful according to one scheduler's speculation,
    // we view it as fact.
    return context.getSchedulers(actionInfo.getActionName())
        .stream()
        .anyMatch(scheduler -> scheduler.isSuccessfulBySpeculation(actionInfo));
  }
}
