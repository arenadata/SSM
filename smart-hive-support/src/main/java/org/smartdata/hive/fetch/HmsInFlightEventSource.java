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
package org.smartdata.hive.fetch;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static lombok.AccessLevel.PROTECTED;
import static org.smartdata.hdfs.HadoopUtil.doAsCurrentUserThrowing;
import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;

@Slf4j
public class HmsInFlightEventSource extends BaseHmsEventSource {
  public static final long INITIAL_DIFF_ID = 0L;

  private final Supplier<IMetaStoreClient> metaStoreClientSupplier;
  private final ScheduledExecutorService executor;
  private final EventOperationBuilder eventOperationBuilder;
  private final int eventBatchSize;
  private final long fetchPeriodMs;
  @Getter(PROTECTED)
  private final Long endEventId;

  @Getter(AccessLevel.PACKAGE)
  private final BlockingQueue<HmsEventStreamRecord> outputQueue;
  @Getter(AccessLevel.PACKAGE)
  private final BlockingQueue<HmsEventStreamRecord> ignoredEventsQueue;
  private final AtomicBoolean pollStarted;
  private final AtomicBoolean pollFinished;

  @Getter(AccessLevel.PACKAGE)
  private volatile long lastHandledEventId;

  @lombok.Builder(
      builderClassName = "Builder",
      toBuilder = true
  )
  public HmsInFlightEventSource(
      Supplier<IMetaStoreClient> metaStoreClientSupplier,
      ScheduledExecutorService executor,
      long fetchPeriodMs,
      int eventBatchSize,
      Long endEventId
  ) {
    this.metaStoreClientSupplier = metaStoreClientSupplier;
    this.executor = executor;
    this.fetchPeriodMs = fetchPeriodMs;
    this.eventBatchSize = eventBatchSize;
    this.outputQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.ignoredEventsQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.pollStarted = new AtomicBoolean(false);
    this.pollFinished = new AtomicBoolean(false);
    this.endEventId = endEventId;
    this.eventOperationBuilder = new EventOperationBuilder();
  }

  @Override
  public HmsEventStream eventStream() {
    return eventStreamFrom(INITIAL_DIFF_ID);
  }

  @Override
  public HmsEventStream eventStreamFrom(long eventId) {
    if (pollStarted.compareAndSet(false, true)) {
      log.info("Start polling from eventId {}", eventId);
      lastHandledEventId = eventId;
      executor.scheduleAtFixedRate(this::pollRecordsBatch,
          0L, fetchPeriodMs, TimeUnit.MILLISECONDS);
    }
    return new HmsEventStream(outputQueue, ignoredEventsQueue);
  }

  void pollRecordsBatch() {
    try {
      log.debug("Polling records batch from eventId {}", lastHandledEventId);

      doAsCurrentUserThrowing(() -> {
        try (IMetaStoreClient metaStoreClient = metaStoreClientSupplier.get()) {
          pollRecordsBatchAction(metaStoreClient);
        }
      });

      if (pollFinished.get()) {
        close();
      }
    } catch (Exception exception) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", exception);
      close();
    }
  }

  public HmsInFlightEventSource toFiniteFetcher(long endEventId) {
    return toBuilder().endEventId(endEventId).build();
  }

  @Override
  protected void closeAction() {
    outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
    ignoredEventsQueue.add(HmsEventStreamRecord.endOfStreamRecord());
  }

  private void pollRecordsBatchAction(IMetaStoreClient metaStoreClient) {
    try {
      List<NotificationEvent> events = metaStoreClient.getNextNotification(
          lastHandledEventId,
          eventBatchSize,
          null
      ).getEvents();

      if (CollectionUtils.isEmpty(events)) {
        log.debug("No new records from HMS to handle");
        return;
      }

      for (NotificationEvent event : events) {
        if (endEventId != null && event.getEventId() > endEventId) {
          log.info("Stopping polling on event {}", event);
          pollFinished.set(true);
          return;
        }

        handle(event);
      }
    } catch (Exception e) {
      throw new RuntimeException("Error polling records batch from Hive Metastore", e);
    }
  }

  private void handle(NotificationEvent event) {
    try {
      log.debug("Handling event {} with type {} and name: {}",
          event.getEventId(), event.getEventType(), fullResourceName(event));

      EventOperation eventOperation = eventOperationBuilder.from(event);

      if (eventOperation.shouldBeProcessed()) {
        handleEvent(event, eventOperation);
      } else {
        handleIgnoredEvent(event);
      }

      // it's guaranteed that events are sorted by eventId in the batch
      lastHandledEventId = event.getEventId();
    } catch (Exception e) {
      log.error("Error handling hive event", e);
    }
  }

  private void handleEvent(NotificationEvent event,
      EventOperation eventOperation) throws InterruptedException {
    HiveNotificationEvent ssmEvent = HiveNotificationEvent.fromMetastoreEvent(event)
        .entityType(eventOperation.getEntity().toString())
        .eventType(eventOperation.getOperation().toString())
        .build();

    outputQueue.put(ssmEvent);
  }

  private void handleIgnoredEvent(NotificationEvent event) throws InterruptedException {
    HiveNotificationEvent ignoredEvent = HiveNotificationEvent.fromMetastoreEvent(event)
        .entityType(HiveEntity.UNKNOWN.toString())
        .eventType(event.getEventType())
        .build();

    ignoredEventsQueue.put(ignoredEvent);
  }
}
