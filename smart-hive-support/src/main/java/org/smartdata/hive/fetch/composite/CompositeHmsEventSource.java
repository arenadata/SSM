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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.smartdata.hive.fetch.BaseHmsEventSource;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.snapshot.HmsSnapshotEventSource;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.INTERMEDIATE_EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.SNAPSHOT_STARTED;
import static org.smartdata.hive.fetch.composite.NewHiveSourceStateRecord.newStateRecord;

@Slf4j
public class CompositeHmsEventSource extends BaseHmsEventSource {

  private final IMetaStoreClient metaStoreClient;
  private final HmsSnapshotEventSource snapshotFetcher;
  private final HmsInFlightEventSource eventFetcher;
  private final ExecutorService executor;

  @Getter
  private final BlockingQueue<HmsEventStreamRecord> outputQueue;
  private final BlockingQueue<HmsEventStreamRecord> unhandledOutputQueue;
  private final AtomicBoolean pollStarted;

  @lombok.Builder(builderClassName = "Builder")
  public CompositeHmsEventSource(
      IMetaStoreClient metaStoreClient,
      HmsSnapshotEventSource snapshotFetcher,
      HmsInFlightEventSource eventFetcher,
      ExecutorService executor,
      int eventBatchSize
  ) {
    this.metaStoreClient = metaStoreClient;
    this.snapshotFetcher = snapshotFetcher;
    this.eventFetcher = eventFetcher;
    this.executor = executor;
    this.outputQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.unhandledOutputQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.pollStarted = new AtomicBoolean(false);
  }

  @Override
  public HmsEventStream eventStream() {
    if (pollStarted.compareAndSet(false, true)) {
      log.info("Start composite hive metastore event fetcher");
      executor.submit(this::multiPhaseFetch);
    }
    return new HmsEventStream(outputQueue, unhandledOutputQueue);
  }

  @Override
  public HmsEventStream eventStreamFrom(long fromEventId) {
    if (pollStarted.compareAndSet(false, true)) {
      log.info("Start simple hive metastore event fetcher");
      executor.submit(() -> fetchMetastoreEventsDirectly(fromEventId));
    }
    return new HmsEventStream(outputQueue, unhandledOutputQueue);
  }

  @Override
  protected void closeAction() {
    if (executor != null) {
      executor.shutdown();
    }

    try {
      metaStoreClient.close();
    } catch (Exception e) {
      log.error("Error closing HiveMetastore client", e);
    }

    outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
    unhandledOutputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
  }

  void fetchMetastoreEventsDirectly(long fromEventId) {
    try {
      outputQueue.put(newStateRecord(EVENTS_STARTED));

      log.info("Start fetching Hive events using event fetcher from id {}", fromEventId);
      pollRecords(eventFetcher, fromEventId, true);
    } catch (Exception retryException) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", retryException);
      close();
    } finally {
      sendEof();
    }
  }

  void multiPhaseFetch() {
    try {
      // 1. Snapshot phase
      log.info("Start fetching Hive entities using snapshot fetcher");
      outputQueue.put(newStateRecord(SNAPSHOT_STARTED));

      long eventIdBeforeSnapshot = metaStoreClient.getCurrentNotificationEventId().getEventId();
      pollRecords(snapshotFetcher, eventIdBeforeSnapshot, false);
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

      outputQueue.put(newStateRecord(EVENTS_STARTED));
      pollRecords(eventFetcher, eventIdAfterSnapshot, true);
    } catch (Exception retryException) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", retryException);
      close();
    } finally {
      sendEof();
    }
  }

  private void resolveUnhandledEvents(long eventIdBeforeSnapshot,
      long eventIdAfterSnapshot) throws Exception {
    outputQueue.put(newStateRecord(INTERMEDIATE_EVENTS_STARTED));

    HmsInFlightEventSource unhandledEventsFetcher = eventFetcher.toFiniteFetcher(eventIdAfterSnapshot);
    pollRecords(unhandledEventsFetcher, eventIdBeforeSnapshot, true);
  }

  private void pollRecords(
      HmsEventSource fetcher,
      long fromEventId,
      boolean forwardUnprocessedRecords) {
    HmsEventStream sourceStream = fetcher.eventStreamFrom(fromEventId);
    Future<?> ignoredEventsFuture = forwardUnprocessedRecords
        ? executor.submit(() -> handleUnprocessedEvents(sourceStream.getIgnoredEvents()))
        : CompletableFuture.completedFuture(null);

    try {
      forwardEvents(sourceStream.getEvents(), outputQueue);
    } catch (InterruptedException e) {
      outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
      log.warn("Error polling records", e);
    } finally {
      ignoredEventsFuture.cancel(true);
      fetcher.close();
    }
  }

  private void handleUnprocessedEvents(BlockingQueue<HmsEventStreamRecord> ignoredEvents) {
    try {
      forwardEvents(ignoredEvents, unhandledOutputQueue);
    } catch (InterruptedException e) {
      log.debug("Interrupting unprocessed events handler", e);
    }
  }

  private void sendEof() {
    closeQueue(outputQueue);
    closeQueue(unhandledOutputQueue);
  }

  private void forwardEvents(
      BlockingQueue<HmsEventStreamRecord> source,
      BlockingQueue<HmsEventStreamRecord> destination
  ) throws InterruptedException {
    HmsEventStreamRecord event;
    do {
      event = source.take();
      // if we encounter the last record marker
      // in the ignored events queue for some reason
      if (!event.isLastRecord()) {
        destination.put(event);
      }
    } while (!event.isLastRecord());
  }
}
