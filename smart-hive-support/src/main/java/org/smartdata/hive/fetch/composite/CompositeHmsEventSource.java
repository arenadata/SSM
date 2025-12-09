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

package org.smartdata.hive.fetch.composite;

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.smartdata.hive.fetch.BaseHmsEventSource;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.snapshot.HmsSnapshotEventSource;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.INTERMEDIATE_EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.SNAPSHOT_STARTED;
import static org.smartdata.hive.fetch.composite.NewHiveSourceStateRecord.newStateRecord;

@Slf4j
public class CompositeHmsEventSource extends BaseHmsEventSource {

  private final Supplier<IMetaStoreClient> metaStoreClientSupplier;
  private final HmsSnapshotEventSource snapshotFetcher;
  private final HmsInFlightEventSource eventFetcher;
  private final ExecutorService executor;

  private final AtomicBoolean pollStarted;

  @lombok.Builder(builderClassName = "Builder")
  public CompositeHmsEventSource(
      Supplier<IMetaStoreClient> metaStoreClientSupplier,
      HmsSnapshotEventSource snapshotFetcher,
      HmsInFlightEventSource eventFetcher,
      ExecutorService executor,
      int eventBatchSize
  ) {
    super(HmsEventFilter.noOp(), eventBatchSize);
    this.metaStoreClientSupplier = metaStoreClientSupplier;
    this.snapshotFetcher = snapshotFetcher;
    this.eventFetcher = eventFetcher;
    this.executor = executor;
    this.pollStarted = new AtomicBoolean(false);
  }

  @Override
  public HmsEventStream eventStream() {
    if (pollStarted.compareAndSet(false, true)) {
      log.info("Start composite hive metastore event fetcher");
      executor.submit(this::multiPhaseFetch);
    }
    return outputStream();
  }

  @Override
  public HmsEventStream eventStreamFrom(long fromEventId) {
    if (pollStarted.compareAndSet(false, true)) {
      log.info("Start simple hive metastore event fetcher");
      executor.submit(() -> fetchMetastoreEventsDirectly(fromEventId));
    }
    return outputStream();
  }

  @Override
  protected void closeAction() {
    if (executor != null) {
      executor.shutdown();
    }

    sendEof();
  }

  void fetchMetastoreEventsDirectly(long fromEventId) {
    try {
      stateTransition(EVENTS_STARTED);

      log.info("Start fetching Hive events using event fetcher from id {}", fromEventId);
      pollRecords(eventFetcher, fromEventId);
    } catch (Exception retryException) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", retryException);
      close();
    } finally {
      sendEofIfNotClosed();
    }
  }

  void multiPhaseFetch() {
    try (IMetaStoreClient metaStoreClient = metaStoreClientSupplier.get()) {
      // 1. Snapshot phase
      log.info("Start fetching Hive entities using snapshot fetcher");
      stateTransition(SNAPSHOT_STARTED);

      long eventIdBeforeSnapshot = metaStoreClient.getCurrentNotificationEventId().getEventId();
      pollRecords(snapshotFetcher, eventIdBeforeSnapshot);
      long eventIdAfterSnapshot = metaStoreClient.getCurrentNotificationEventId().getEventId();

      log.info("Hive entities initial fetch successfully finished");

      // 2. Optional intermediate events phase
      if (eventIdBeforeSnapshot != eventIdAfterSnapshot) {
        log.info("Start resolving missed Hive entity diffs using conflict resolver:" +
            " events from {} to {}", eventIdBeforeSnapshot, eventIdAfterSnapshot);
        resolveUnhandledEvents(eventIdBeforeSnapshot, eventIdAfterSnapshot);
      }

      // 3. Hive metastore events phase
      log.info("Start fetching Hive entity diffs using event fetcher from id {}", eventIdAfterSnapshot);

      stateTransition(EVENTS_STARTED);
      pollRecords(eventFetcher, eventIdAfterSnapshot);
    } catch (Exception retryException) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", retryException);
      close();
    } finally {
      sendEofIfNotClosed();
    }
  }

  private void resolveUnhandledEvents(long eventIdBeforeSnapshot,
      long eventIdAfterSnapshot) throws Exception {
    stateTransition(INTERMEDIATE_EVENTS_STARTED);

    HmsInFlightEventSource unhandledEventsFetcher = eventFetcher.toFiniteFetcher(eventIdAfterSnapshot);
    pollRecords(unhandledEventsFetcher, eventIdBeforeSnapshot);
  }

  private void stateTransition(HiveDiffSourceState newState) throws InterruptedException {
    outputQueue.put(newStateRecord(newState));
  }

  private void pollRecords(
      HmsEventSource fetcher,
      long fromEventId) {
    HmsEventStream sourceStream = fetcher.eventStreamFrom(fromEventId);
    Future<?> ignoredEventsFuture = executor.submit(
        () -> handleUnprocessedEvents(sourceStream.getIgnoredEvents()));

    try {
      forwardEvents(sourceStream.getEvents(), outputQueue);
    } catch (InterruptedException e) {
      outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
      log.warn("Error polling records", e);
    } finally {
      ignoredEventsFuture.cancel(false);
      fetcher.close();
    }
  }

  private void handleUnprocessedEvents(BlockingQueue<HmsEventStreamRecord> ignoredEvents) {
    try {
      forwardEvents(ignoredEvents, ignoredEventsQueue);
    } catch (InterruptedException e) {
      ignoredEventsQueue.add(HmsEventStreamRecord.endOfStreamRecord());
      log.debug("Interrupting unprocessed events handler", e);
    }
  }

  private void forwardEvents(
      BlockingQueue<HmsEventStreamRecord> source,
      BlockingQueue<HmsEventStreamRecord> destination
  ) throws InterruptedException {
    HmsEventStreamRecord event;
    do {
      event = source.take();
      if (!event.isLastRecord()) {
        destination.put(event);
      }
    } while (!event.isLastRecord());
  }
}
