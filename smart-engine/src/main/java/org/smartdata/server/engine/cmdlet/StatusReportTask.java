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

import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.protocol.message.ActionStatus;
import org.smartdata.protocol.message.StatusReport;
import org.smartdata.protocol.message.StatusReporter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class StatusReportTask implements Runnable {
  private final StatusReporter statusReporter;
  private final CmdletExecutor cmdletExecutor;
  private final int interval;
  private final double ratio;
  private final Map<Long, ActionStatus> idToActionStatus;
  private long lastReportTime;

  public StatusReportTask(
      StatusReporter statusReporter, CmdletExecutor cmdletExecutor, SmartConf conf) {
    this.statusReporter = statusReporter;
    this.cmdletExecutor = cmdletExecutor;
    this.lastReportTime = System.currentTimeMillis();
    int period = conf.getInt(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_DEFAULT);
    int multiplier = conf.getInt(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_MULTIPLIER_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_PERIOD_MULTIPLIER_DEFAULT);
    this.interval = period * multiplier;
    this.ratio = conf.getDouble(SmartConfKeys.SMART_STATUS_REPORT_RATIO_KEY,
        SmartConfKeys.SMART_STATUS_REPORT_RATIO_DEFAULT);
    this.idToActionStatus = new HashMap<>();
  }

  public void run() {
    Optional.ofNullable(cmdletExecutor.getStatusReport())
        .map(StatusReport::getActionStatuses)
        .orElseGet(Collections::emptyList)
        .forEach(status -> idToActionStatus.put(status.getActionId(), status));

    if (idToActionStatus.isEmpty()) {
      return;
    }
    long finishedNum = idToActionStatus.values()
        .stream()
        .filter(ActionStatus::isFinished)
        .count();

    long currentTime = System.currentTimeMillis();
    if (currentTime - lastReportTime >= interval
        || (double) finishedNum / idToActionStatus.size() >= ratio) {
      statusReporter.report(new StatusReport(new ArrayList<>(idToActionStatus.values())));
      idToActionStatus.clear();
      lastReportTime = currentTime;
    }
  }
}
