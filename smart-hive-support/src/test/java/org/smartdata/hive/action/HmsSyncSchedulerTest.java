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

import com.google.common.collect.ImmutableMap;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.SmartContext;
import org.smartdata.conf.SmartConf;
import org.smartdata.hive.EntityInfo;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.action.db.HmsCreateDbAction;
import org.smartdata.hive.fetch.EventOperation;
import org.smartdata.hive.fetch.EventOperationBuilder;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.hive.rule.HmsSyncProgressDao;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.action.ScheduleResult;
import org.smartdata.protocol.message.LaunchCmdlet;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.assertEquals;
import static org.smartdata.hive.NotificationEventFactory.newAlterDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateTableEvent;
import static org.smartdata.hive.action.HmsAction.EVENT_MESSAGE;
import static org.smartdata.hive.action.HmsAction.EVENT_MESSAGE_FORMAT;
import static org.smartdata.hive.action.HmsSyncAction.ENTITY_NAME;
import static org.smartdata.model.action.ScheduleResult.RETRY;
import static org.smartdata.model.action.ScheduleResult.SUCCESS;
import static org.smartdata.model.action.ScheduleResult.SUCCESS_NO_EXECUTION;

@Slf4j
public class HmsSyncSchedulerTest {
  private static final long EVENT_ID = 777L;
  private static final long RULE_ID = 1L;

  private MockHmsSyncProgressDao syncProgressDao;
  private MockHmsEventDao eventDao;
  private HmsSyncScheduler scheduler;

  @Before
  public void setUp() {
    SmartConf conf = new SmartConf();
    eventDao = new MockHmsEventDao();
    syncProgressDao = new MockHmsSyncProgressDao();
    scheduler = new HmsSyncScheduler(new SmartContext(conf), eventDao, syncProgressDao);
  }

  @Test
  public void testSkipEntityInProcessing() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(EVENT_ID, "hive.db1", "/location"))
    );

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(EVENT_ID, RULE_ID),
        launchCmdlet(EVENT_ID, RULE_ID),
        launchAction(EVENT_ID, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(EVENT_ID, RULE_ID),
        launchCmdlet(EVENT_ID, RULE_ID),
        launchAction(EVENT_ID, RULE_ID)
    );
    assertEquals(RETRY, scheduleResult);
  }

  @Test
  public void testProcessSameEntityInDifferentRules() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(EVENT_ID, "hive.db1", "/location"))
    );

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(EVENT_ID, 1L),
        launchCmdlet(EVENT_ID, 1L),
        launchAction(EVENT_ID, 1L)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(EVENT_ID, 2L),
        launchCmdlet(EVENT_ID, 2L),
        launchAction(EVENT_ID, 2L)
    );
    assertEquals(SUCCESS, scheduleResult);
  }

  @Test
  public void testSkipEventsOlderThanWatermark() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1000L, "hive.db1", "/location")),
        ssmEvent(newCreateDbEvent(1L, "hive.db2", "/location"))
    );

    ActionInfo finishedAction = actionInfo(1000L, RULE_ID);
    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        finishedAction,
        launchCmdlet(1000L, RULE_ID),
        launchAction(1000L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduler.onActionFinished(cmdletInfo(), finishedAction);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(1L, RULE_ID),
        launchCmdlet(1L, RULE_ID),
        launchAction(1L, RULE_ID)
    );
    assertEquals(SUCCESS_NO_EXECUTION, scheduleResult);

    // check doesn't affect other rules
    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(1L, 2L),
        launchCmdlet(1L, 2L),
        launchAction(1L, 2L)
    );
    assertEquals(SUCCESS, scheduleResult);
  }

  @Test
  public void testRetryLockedEvents() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1L, "hive.db", "/location/1")),
        ssmEvent(newAlterDbEvent(2L,
            new EntityInfo("hive.db", "/location/1"),
            new EntityInfo("hive.db2", "/location/2")))
    );

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(1L, RULE_ID),
        launchCmdlet(1L, RULE_ID),
        launchAction(1L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(2L, RULE_ID),
        launchCmdlet(2L, RULE_ID),
        launchAction(2L, RULE_ID)
    );
    assertEquals(RETRY, scheduleResult);

    // check doesn't affect other rules
    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(2L, 2L),
        launchCmdlet(2L, 2L),
        launchAction(2L, 2L)
    );
    assertEquals(SUCCESS, scheduleResult);
  }

  @Test
  public void testRetryLockedChildEvents() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1L, "hive.db", "/location/1")),
        ssmEvent(newCreateDbEvent(2L, "hive.db2", "/location/2")),
        ssmEvent(newCreateTableEvent(3L, "hive.db.table", TableType.EXTERNAL_TABLE, "/location/1/tb"))
    );

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(1L, RULE_ID),
        launchCmdlet(1L, RULE_ID),
        launchAction(1L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(3L, RULE_ID),
        launchCmdlet(3L, RULE_ID),
        launchAction(3L, RULE_ID)
    );
    assertEquals(RETRY, scheduleResult);

    // check doesn't affect other rules
    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(3L, 2L),
        launchCmdlet(3L, 2L),
        launchAction(3L, 2L)
    );
    assertEquals(SUCCESS, scheduleResult);
  }

  @Test
  public void testRetryParentEntitiesWithChildLock() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1L, "hive.db", "/location/1")),
        ssmEvent(newCreateTableEvent(2L, "hive.db.table", TableType.EXTERNAL_TABLE, "/location/1/tb"))
    );

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(2L, RULE_ID),
        launchCmdlet(2L, RULE_ID),
        launchAction(2L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(1L, RULE_ID),
        launchCmdlet(1L, RULE_ID),
        launchAction(1L, RULE_ID)
    );
    assertEquals(RETRY, scheduleResult);
  }

  @Test
  public void testOnSchedule() {
    HiveNotificationEvent hiveEvent = ssmEvent(
        newCreateDbEvent(1L, "hive.db", "/location/1"));
    eventDao.insert(hiveEvent);

    ActionInfo actionInfo = actionInfo(1L, RULE_ID);
    LaunchAction launchAction = launchAction(1L, RULE_ID);

    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo,
        launchCmdlet(1L, RULE_ID),
        launchAction
    );

    assertEquals(SUCCESS, scheduleResult);
    assertEquals("db", actionInfo.getArgs().get(ENTITY_NAME));
    assertEquals(HmsCreateDbAction.NAME, launchAction.getActionType());
    assertEquals(hiveEvent.getMessage(), launchAction.getArgs().get(EVENT_MESSAGE));
    assertEquals(hiveEvent.getMessageFormat(), launchAction.getArgs().get(EVENT_MESSAGE_FORMAT));
  }

  @Test
  public void testOnActionFinished() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1L, "hive.db1", "/location/1")),
        ssmEvent(newCreateDbEvent(2L, "hive.db2", "/location/2")),
        ssmEvent(newCreateDbEvent(3L, "hive.db3", "/location/3"))
    );

    ActionInfo actionInfo1 = actionInfo(1L, 1L);
    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo1,
        launchCmdlet(1L, 1L),
        launchAction(1L, 1L)
    );
    assertEquals(SUCCESS, scheduleResult);

    ActionInfo actionInfo2 = actionInfo(2L, 2L);
    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo2,
        launchCmdlet(2L, 2L),
        launchAction(2L, 2L)
    );
    assertEquals(SUCCESS, scheduleResult);

    ActionInfo actionInfo3 = actionInfo(3L, 1L);
    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo3,
        launchCmdlet(3L, 1L),
        launchAction(3L, 1L)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduler.onActionFinished(cmdletInfo(), actionInfo3);
    scheduler.onActionFinished(cmdletInfo(), actionInfo2);
    scheduler.onActionFinished(cmdletInfo(), actionInfo1);
    scheduler.flushRuleProgress();

    assertEquals(
        ImmutableMap.of(
            1L, 3L,
            2L, 2L
        ),
        syncProgressDao.progressMap);
  }

  @Test
  public void testRemoveLockAfterActionFinished() {
    eventDao.insert(
        ssmEvent(newCreateDbEvent(1L, "hive.db", "/location")),
        ssmEvent(newCreateTableEvent(2L, "hive.db.table", TableType.EXTERNAL_TABLE, "/location/tb"))
    );

    ActionInfo finishedAction = actionInfo(1L, RULE_ID);
    ScheduleResult scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        finishedAction,
        launchCmdlet(1L, RULE_ID),
        launchAction(1L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);

    scheduler.onActionFinished(cmdletInfo(), finishedAction);

    scheduleResult = scheduler.onSchedule(
        cmdletInfo(),
        actionInfo(2L, RULE_ID),
        launchCmdlet(2L, RULE_ID),
        launchAction(2L, RULE_ID)
    );
    assertEquals(SUCCESS, scheduleResult);
  }

  private LaunchCmdlet launchCmdlet(long eventId, long ruleId) {
    return new LaunchCmdlet(1L, Collections.singletonList(
        launchAction(eventId, ruleId)
    ), "owner");
  }

  private CmdletInfo cmdletInfo() {
    return CmdletInfo.builder().build();
  }

  private ActionInfo actionInfo(long eventId, long ruleId) {
    Map<String, String> args = new HashMap<>();
    args.put(CmdletDescriptor.RULE_ID, String.valueOf(ruleId));
    args.put(CmdletDescriptor.OBJECT_ID, String.valueOf(eventId));
    return ActionInfo.builder()
        .setActionName(HmsSyncAction.NAME)
        .setArgs(args)
        .build();
  }

  private LaunchAction launchAction(long eventId, long ruleId) {
    Map<String, String> args = new HashMap<>();
    args.put(CmdletDescriptor.RULE_ID, String.valueOf(ruleId));
    args.put(CmdletDescriptor.OBJECT_ID, String.valueOf(eventId));
    return new LaunchAction(
        777L,
        HmsSyncAction.NAME,
        args
    );
  }

  private HiveNotificationEvent ssmEvent(NotificationEvent event) {
    EventOperation eventOperation = new EventOperationBuilder().from(event);
    return HiveNotificationEvent.fromMetastoreEvent(event)
        .id(event.getEventId())
        .entityType(eventOperation.getEntity().toString())
        .eventType(eventOperation.getOperation() == HiveOperation.UNKNOWN
            ? event.getEventType()
            : eventOperation.getOperation().toString()
        ).build();
  }

  private static class MockHmsSyncProgressDao implements HmsSyncProgressDao {

    private final Map<Long, Long> progressMap = new ConcurrentHashMap<>();

    @Override
    public void insertIfNotPresent(long ruleId, long lastHandledEventId) {
      progressMap.putIfAbsent(ruleId, lastHandledEventId);
    }

    @Override
    public void upsert(Map<Long, Long> ruleProgress) {
      progressMap.putAll(ruleProgress);
    }
  }

  private static class MockHmsEventDao implements HmsEventDao {

    private final NavigableMap<Long, HiveNotificationEvent> events = new TreeMap<>();

    public void insert(HiveNotificationEvent... events) {
      for (HiveNotificationEvent event : events) {
        insert(event);
      }
    }

    @Override
    public void insert(HiveNotificationEvent event) {
      events.put(event.getId(), event);
    }

    @Override
    public void insertIfNotPresent(HiveNotificationEvent event) {
      // this method is not used here
      insert(event);
    }

    @Override
    public HiveNotificationEvent get(long eventId) {
      return events.computeIfAbsent(eventId, ignore -> {
        throw new IllegalArgumentException("Event with id not found: " + eventId);
      });
    }

    @Override
    public void deleteAll() {
      events.clear();
    }

    @Override
    public void deleteEventsFor(String fullName) {
      events.values().removeIf(event -> fullName.equals(event.getFullName()));
    }

    @Override
    public Optional<Long> getLatestExternalEventId() {
      try {
        return Optional.of(events.lastKey());
      } catch (Exception e) {
        return Optional.empty();
      }
    }

    @Override
    public <T> T execute(TransactionCallback<T> action) throws TransactionException {
      return action.doInTransaction(new SimpleTransactionStatus());
    }
  }
}