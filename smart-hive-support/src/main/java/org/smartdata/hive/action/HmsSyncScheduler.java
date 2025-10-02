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
package org.smartdata.hive.action;

import org.smartdata.SmartContext;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.rule.HmsSyncProgressDao;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.action.ActionSchedulerService;
import org.smartdata.model.action.ScheduleResult;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

public class HmsSyncScheduler extends ActionSchedulerService {
  private final HmsSyncProgressDao hmsSyncProgressDao;
  private final HmsEventDao hmsEventDao;
  // todo currently used just for the testing purposes until
  // proper scheduler implementation and actions will be added
  private final SortedSet<Long> eventsInAction;

  public HmsSyncScheduler(SmartContext context,
      HmsEventDao hmsEventDao,
      HmsSyncProgressDao hmsSyncProgressDao) {
    super(context);
    this.hmsSyncProgressDao = hmsSyncProgressDao;
    this.hmsEventDao = hmsEventDao;
    this.eventsInAction = new ConcurrentSkipListSet<>();
  }

  @Override
  public ScheduleResult onSchedule(CmdletInfo cmdletInfo, ActionInfo actionInfo, LaunchCmdlet cmdlet,
      LaunchAction action) {
    long objectId = objectId(actionInfo);
    boolean isNewAction = eventsInAction.add(objectId);
    if (!isNewAction) {
      return ScheduleResult.SUCCESS_NO_EXECUTION;
    }

    HiveNotificationEvent event = hmsEventDao.get(objectId);
    // todo tmp arg for testing purposes
    // until we implement proper sync actions
    action.getArgs().put(HmsSyncAction.OBJECT, event.getFullName());

    return ScheduleResult.SUCCESS;
  }

  @Override
  public void onActionFinished(CmdletInfo cmdletInfo, ActionInfo actionInfo) {
    long objectId = objectId(actionInfo);
    eventsInAction.remove(objectId);

    if (!eventsInAction.isEmpty()) {
      long lowestEventId = eventsInAction.first();
      hmsSyncProgressDao.upsert(ruleId(actionInfo), lowestEventId);
    }
  }

  @Override
  public void init() throws IOException {

  }

  @Override
  public void start() throws IOException {

  }

  @Override
  public void stop() throws IOException {

  }

  @Override
  public List<String> getSupportedActions() {
    return Collections.singletonList(HmsSyncAction.NAME);
  }

  private long objectId(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(CmdletDescriptor.OBJECT_ID))
        .map(Long::parseLong)
        .orElseThrow(() -> new IllegalArgumentException("Missing object id"));
  }

  private long ruleId(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(CmdletDescriptor.RULE_ID))
        .map(Long::parseLong)
        .orElseThrow(() -> new IllegalArgumentException("Missing rule id"));
  }
}
