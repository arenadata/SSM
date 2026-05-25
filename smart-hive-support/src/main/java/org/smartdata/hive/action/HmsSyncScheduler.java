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
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.smartdata.SmartContext;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;
import org.smartdata.hive.action.constraint.HmsDropConstraintAction;
import org.smartdata.hive.action.db.HmsAlterDbAction;
import org.smartdata.hive.action.db.HmsCreateDbAction;
import org.smartdata.hive.action.db.HmsDropDbAction;
import org.smartdata.hive.action.function.HmsCreateFunctionAction;
import org.smartdata.hive.action.function.HmsDropFunctionAction;
import org.smartdata.hive.action.partition.HmsAlterPartitionAction;
import org.smartdata.hive.action.partition.HmsCreatePartitionAction;
import org.smartdata.hive.action.partition.HmsDropPartitionAction;
import org.smartdata.hive.action.stats.HmsAlterPartitionColumnStatsAction;
import org.smartdata.hive.action.stats.HmsAlterTableColumnStatsAction;
import org.smartdata.hive.action.stats.HmsDropPartitionColumnStatsAction;
import org.smartdata.hive.action.stats.HmsDropTableColumnStatsAction;
import org.smartdata.hive.action.table.HmsAlterTableAction;
import org.smartdata.hive.action.table.HmsCreateTableAction;
import org.smartdata.hive.action.table.HmsDropTableAction;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.hive.rule.HmsSyncProgressDao;
import org.smartdata.hive.util.DefaultTrie;
import org.smartdata.hive.util.Trie;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.action.ActionSchedulerService;
import org.smartdata.model.action.ScheduleResult;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.smartdata.hive.HiveSmartConf.HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS;
import static org.smartdata.hive.HiveSmartConf.HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS_DEFAULT;
import static org.smartdata.hive.action.HmsSyncScheduler.ActionBlueprint.action;
import static org.smartdata.hive.fetch.HiveEntity.CHECK_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.DEFAULT_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.FOREIGN_KEY;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.NOT_NULL_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION_COLUMN_STAT;
import static org.smartdata.hive.fetch.HiveEntity.PRIMARY_KEY;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveEntity.TABLE_COLUMN_STAT;
import static org.smartdata.hive.fetch.HiveEntity.UNIQUE_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveOperation.ALTER;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;

@Slf4j
public class HmsSyncScheduler extends ActionSchedulerService {
  private final static String ENTITY_NAME_DELIMITER = "\\.";
  private static final Map<HiveEntity, Map<HiveOperation, ActionBlueprint>> ENTITY_ACTIONS =
      ImmutableMap.<HiveEntity, Map<HiveOperation, ActionBlueprint>>builder()
          .put(DATABASE, ImmutableMap.of(
              CREATE, action(HmsCreateDbAction.NAME),
              DROP, action(HmsDropDbAction.NAME),
              ALTER, action(HmsAlterDbAction.NAME)
          ))
          .put(TABLE, ImmutableMap.of(
              CREATE, action(HmsCreateTableAction.NAME),
              DROP, action(HmsDropTableAction.NAME),
              ALTER, action(HmsAlterTableAction.NAME)
          ))
          .put(FUNCTION, ImmutableMap.of(
              CREATE, action(HmsCreateFunctionAction.NAME),
              DROP, action(HmsDropFunctionAction.NAME)
          ))
          .put(PARTITION, ImmutableMap.of(
              CREATE, action(HmsCreatePartitionAction.NAME),
              DROP, action(HmsDropPartitionAction.NAME),
              ALTER, action(HmsAlterPartitionAction.NAME)
          ))
          .put(TABLE_COLUMN_STAT, ImmutableMap.of(
              ALTER, action(HmsAlterTableColumnStatsAction.NAME),
              DROP, action(HmsDropTableColumnStatsAction.NAME)
          ))
          .put(PARTITION_COLUMN_STAT, ImmutableMap.of(
              ALTER, action(HmsAlterPartitionColumnStatsAction.NAME),
              DROP, action(HmsDropPartitionColumnStatsAction.NAME)
          ))
          .put(PRIMARY_KEY, constraintActions(PRIMARY_KEY))
          .put(FOREIGN_KEY, constraintActions(FOREIGN_KEY))
          .put(UNIQUE_CONSTRAINT, constraintActions(UNIQUE_CONSTRAINT))
          .put(NOT_NULL_CONSTRAINT, constraintActions(NOT_NULL_CONSTRAINT))
          .put(DEFAULT_CONSTRAINT, constraintActions(DEFAULT_CONSTRAINT))
          .put(CHECK_CONSTRAINT, constraintActions(CHECK_CONSTRAINT))
          .build();


  private final HmsSyncProgressDao hmsSyncProgressDao;
  private final HmsEventDao hmsEventDao;

  private final Map<Long, RuleState> ruleStateMap;

  private final ScheduledExecutorService executorService;
  private final long ruleProgressFlushIntervalMs;

  public HmsSyncScheduler(SmartContext context,
      HmsEventDao hmsEventDao,
      HmsSyncProgressDao hmsSyncProgressDao) {
    super(context);
    this.hmsSyncProgressDao = hmsSyncProgressDao;
    this.hmsEventDao = hmsEventDao;
    this.ruleStateMap = new ConcurrentHashMap<>();
    this.executorService = Executors.newSingleThreadScheduledExecutor();
    this.ruleProgressFlushIntervalMs = context.getConf().getLong(
        HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS,
        HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS_DEFAULT
    );
  }

  @Override
  public ScheduleResult onSchedule(CmdletInfo cmdletInfo, ActionInfo actionInfo, LaunchCmdlet cmdlet,
      LaunchAction action) {
    long eventId = eventId(actionInfo);
    RuleState ruleState = ruleStateMap.computeIfAbsent(
        ruleId(actionInfo), key -> new RuleState(extractAllowedOperations(actionInfo)));

    boolean isNewAction = ruleState.eventsInProcessing.add(eventId);
    if (!isNewAction) {
      log.debug("Event {} is already in processing.", eventId);
      return ScheduleResult.RETRY;
    }

    if (ruleState.handledEvents.contains(eventId)
        || eventId <= ruleState.eventIdWatermark.get()) {
      log.debug("Event with id {} has already been handled for rule {}, skipping",
          eventId, ruleId(actionInfo));
      ruleState.eventsInProcessing.remove(eventId);
      return ScheduleResult.SKIP;
    }

    HiveNotificationEvent event = hmsEventDao.get(eventId);

    if (!isIncludedOperation(event, ruleState)) {
      log.debug("Event with id {} is not included for rule {}, skipping",
          eventId, ruleId(actionInfo));
      onActionFinished(cmdletInfo, actionInfo);
      return ScheduleResult.SKIP;
    }

    if (isLocked(event, ruleState)) {
      log.debug("Entity {} is locked or has locked parent objects. Retrying later.", event.getFullName());
      ruleState.eventsInProcessing.remove(eventId);
      ruleState.addRetryState(event);
      return ScheduleResult.RETRY;
    }

    ruleState.putEntityLock(event);
    ruleState.clearRetryState(event);

    actionInfo.getArgs().put(HmsSyncAction.ENTITY_NAME, event.getFullName());
    Optional.ofNullable(event.rawRelatedResources())
        .ifPresent(resources -> actionInfo.getArgs().put(HmsSyncAction.RELATED_RESOURCES, resources));
    Optional.ofNullable(event.getTableName())
        .ifPresent(tableName -> actionInfo.getArgs().put(HmsSyncAction.TABLE_NAME, tableName));

    try {
      handleEvent(event, action);
      return ScheduleResult.SUCCESS;
    } catch (Exception e) {
      ruleState.clearEventState(event);

      log.error("Error trying to schedule HMS event {}", event, e);
      return ScheduleResult.FAIL;
    }
  }

  @Override
  public void onActionFinished(CmdletInfo cmdletInfo, ActionInfo actionInfo) {
    long eventId = eventId(actionInfo);
    log.debug("Event {} has been handled", eventId);

    RuleState ruleState = getRuleState(actionInfo);
    ruleState.eventsInProcessing.remove(eventId);
    ruleState.handledEvents.add(eventId);

    try {
      // Set the watermark as the id just before the earliest event still in progress
      ruleState.updateWatermark(ruleState.eventsInProcessing.first() - 1);
    } catch (NoSuchElementException e) {
      // There is no way to check the size of eventsInProcessing and get
      // the first element from it atomically except pessimistic locks.
      // We don't want to penalize the performance just for this case,
      // so recover from the exception instead.
      //
      // Set the watermark as the current maxHandledEventId in case
      // if the action with the highest event id finished earlier
      ruleState.updateWatermark(ruleState.getMaxHandledEventId(eventId));
    } finally {
      // Remove the entity lock only after setting the progress of the current rule
      // to cover the case when the same event is scheduled for any reason
      // during the execution of the current method.
      removeLock(ruleState, actionInfo);
    }
  }

  private boolean isIncludedOperation(HiveNotificationEvent event, RuleState ruleState) {
    return Optional.ofNullable(event.getEventType())
        .map(operation -> EnumUtils.getEnum(HiveOperation.class, operation))
        .filter(ruleState::isIncludedOperation)
        .isPresent();
  }

  private boolean isLocked(HiveNotificationEvent event, RuleState ruleState) {
    return isLocked(event, ruleState, event.getFullName())
        || event.getRelatedResources()
        .stream()
        .anyMatch(resourceName -> isLocked(event, ruleState, resourceName));
  }

  private boolean isLocked(HiveNotificationEvent event, RuleState ruleState, String resourceName) {
    return ruleState.isLocked(resourceName)
        || ruleState.hasEventsToRetryForEntity(event, resourceName);
  }

  private void handleEvent(HiveNotificationEvent event, LaunchAction action) {
    log.debug("Starting handling event: {}", event);

    action.getArgs().put(HmsSyncAction.EVENT_MESSAGE, event.getMessage());
    action.getArgs().put(HmsSyncAction.EVENT_MESSAGE_FORMAT, event.getMessageFormat());

    HiveEntity hiveEntity = HiveEntity.valueOf(event.getEntityType());
    HiveOperation hiveOperation = HiveOperation.valueOf(event.getEventType());

    ActionBlueprint actionBluePrint = Optional.ofNullable(ENTITY_ACTIONS.get(hiveEntity))
        .map(actions -> actions.get(hiveOperation))
        .orElseThrow(() -> new IllegalArgumentException(
            "Unexpected Hive operation type: " + event.getEntityType() + " for entity: " + hiveEntity));
    actionBluePrint.mutate(action);

    log.debug("Event successfully transformed to action '{}'", action);
  }

  @Override
  public void init() throws IOException {

  }

  @Override
  public void start() throws IOException {
    executorService.scheduleAtFixedRate(
        this::flushRuleProgress, 0, ruleProgressFlushIntervalMs,
        TimeUnit.MILLISECONDS);
  }

  @Override
  public void stop() throws IOException {
    executorService.shutdown();
    flushRuleProgress();
  }

  @Override
  public List<String> getSupportedActions() {
    return Collections.singletonList(HmsSyncAction.NAME);
  }

  private void removeLock(RuleState ruleState, ActionInfo actionInfo) {
    getEntityName(actionInfo)
        .ifPresent(entityName -> {
              ruleState.removeLock(entityName);
              getRelatedResources(actionInfo).forEach(ruleState::removeLock);
            }
        );
  }

  private long eventId(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(CmdletDescriptor.OBJECT_ID))
        .map(Long::parseLong)
        .orElseThrow(() -> new IllegalArgumentException("Missing object id"));
  }

  private long ruleId(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(CmdletDescriptor.RULE_ID))
        .map(Long::parseLong)
        .orElseThrow(() -> new IllegalArgumentException("Missing rule id"));
  }

  private Optional<String> getEntityName(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(HmsSyncAction.ENTITY_NAME));
  }

  private Set<String> getRelatedResources(ActionInfo actionInfo) {
    return Optional.ofNullable(actionInfo.getArgs().get(HmsSyncAction.RELATED_RESOURCES))
        .map(HiveNotificationEvent::extractRelatedResources)
        .orElseGet(Collections::emptySet);
  }

  private RuleState getRuleState(ActionInfo actionInfo) {
    long ruleId = ruleId(actionInfo);
    return ruleStateMap.computeIfAbsent(ruleId, key -> {
      throw new IllegalArgumentException(
          "No rule id argument found, hms-sync action should only be used inside rules");
    });
  }

  void flushRuleProgress() {
    Map<Long, Long> ruleProgressSnapshot = ruleStateMap.entrySet()
        .stream()
        .collect(Collectors.toMap(
            Map.Entry::getKey,
            entry -> entry.getValue().eventIdWatermark.get())
        );

    hmsSyncProgressDao.upsert(ruleProgressSnapshot);
  }

  private Set<HiveOperation> extractAllowedOperations(ActionInfo actionInfo) {
    Set<HiveOperation> included = toHiveOperations(actionInfo.getArgs().get(HmsSyncAction.INCLUDE));
    if (!included.isEmpty()) {
      return included;
    }

    Set<HiveOperation> allowedOperations = new HashSet<>(HiveOperation.FILTERABLE_OPERATIONS);
    allowedOperations.removeAll(toHiveOperations(actionInfo.getArgs().get(HmsSyncAction.EXCLUDE)));
    return allowedOperations;
  }

  private Set<HiveOperation> toHiveOperations(String rawOperations) {
    return Optional.ofNullable(rawOperations)
        .map(operations -> Arrays.stream(operations.split(","))
            .map(String::toUpperCase)
            .map(operation -> EnumUtils.getEnum(HiveOperation.class, operation.trim()))
            .filter(HiveOperation::isFilterable)
            .collect(Collectors.toSet()))
        .orElse(Collections.emptySet());
  }

  static Trie.Key<String> trieKey(String entityName) {
    return Optional.ofNullable(entityName)
        .map(name -> name.split(ENTITY_NAME_DELIMITER))
        .map(Trie.Key::new)
        .orElse(null);
  }

  private static Map<HiveOperation, ActionBlueprint> constraintActions(HiveEntity constraintType) {
    return ImmutableMap.of(
        CREATE, action(HmsCreateConstraintAction.NAME)
            .withArg(HmsCreateConstraintAction.TYPE, constraintType),
        DROP, action(HmsDropConstraintAction.NAME)
    );
  }

  @Data
  static class RuleState {
    private final NavigableSet<Long> eventsInProcessing = new ConcurrentSkipListSet<>();
    private final NavigableSet<Long> handledEvents = new ConcurrentSkipListSet<>();
    private final Trie<String, Boolean> entityLocks = Trie.synchronize(new DefaultTrie<>());
    // the max id of the handled event for which all prior events have also been handled
    private final AtomicLong eventIdWatermark = new AtomicLong(Long.MIN_VALUE);

    // retry events state
    private final NavigableSet<Long> retryEvents = new ConcurrentSkipListSet<>();
    private final Trie<String, Long> retryEntityLocks = Trie.synchronize(new DefaultTrie<>());

    private final Set<HiveOperation> includedOperations;

    RuleState(Set<HiveOperation> includedOperations) {
      this.includedOperations = includedOperations;
    }

    void putEntityLock(HiveNotificationEvent event) {
      forEntityAndRelatedResources(event, resource ->
          entityLocks.putIfNoIntersectingLocks(trieKey(resource), true));
    }

    boolean isIncludedOperation(HiveOperation operation) {
      return includedOperations.contains(operation);
    }

    boolean isLocked(String resourceName) {
      return entityLocks.getIntersectingLock(trieKey(resourceName)).isPresent();
    }

    boolean hasEventsToRetryForEntity(HiveNotificationEvent event, String resourceName) {
      return retryEntityLocks
          .getIntersectingLock(trieKey(resourceName))
          .map(lockEventId -> lockEventId != event.getId())
          .orElse(false);
    }

    void addRetryState(HiveNotificationEvent event) {
      retryEvents.add(event.getId());
      forEntityAndRelatedResources(event, resource ->
          retryEntityLocks.putIfNoIntersectingLocks(trieKey(resource), event.getId()));
    }

    void clearRetryState(HiveNotificationEvent event) {
      retryEvents.remove(event.getId());
      forEntityAndRelatedResources(event,
          resource -> retryEntityLocks.remove(trieKey(resource)));
    }

    void clearEventState(HiveNotificationEvent event) {
      eventsInProcessing.remove(event.getId());
      forEntityAndRelatedResources(event, this::removeLock);
      clearRetryState(event);
    }

    void forEntityAndRelatedResources(HiveNotificationEvent event,
        Consumer<String> resourceConsumer) {
      resourceConsumer.accept(event.getFullName());
      event.getRelatedResources().forEach(resourceConsumer);
    }

    void removeLock(String entityName) {
      entityLocks.remove(trieKey(entityName));
    }

    void updateWatermark(long eventId) {
      long watermarkEventId = eventIdWatermark
          .updateAndGet(currentId ->
              Math.max(currentId, getLastHandledEventIdBeforeRetries(eventId)));
      handledEvents
          .removeIf(handledEventId -> handledEventId <= watermarkEventId);
    }

    private long getLastHandledEventIdBeforeRetries(long defaultEventId) {
      try {
        return retryEvents.first() - 1;
      } catch (NoSuchElementException exception) {
        // There is no way to check the size of handledEvents and get
        // the last element from it atomically except pessimistic locks.
        // We don't want to penalize the performance just for this case,
        // so recover from the exception instead
        return defaultEventId;
      }
    }

    private long getMaxHandledEventId(long defaultEventId) {
      try {
        return handledEvents.last();
      } catch (NoSuchElementException exception) {
        // There is no way to check the size of handledEvents and get
        // the last element from it atomically except pessimistic locks.
        // We don't want to penalize the performance just for this case,
        // so recover from the exception instead
        return defaultEventId;
      }
    }
  }

  @Data
  static class ActionBlueprint {
    private final String actionName;
    private final Map<String, String> args = new HashMap<>();

    public ActionBlueprint withArg(String key, Object value) {
      args.put(key, value.toString());
      return this;
    }

    public void mutate(LaunchAction action) {
      action.setActionType(actionName);
      action.getArgs().putAll(args);
    }

    public static ActionBlueprint action(String actionName) {
      return new ActionBlueprint(actionName);
    }
  }
}
