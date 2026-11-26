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

import lombok.Getter;
import org.smartdata.hive.fetch.enrich.HmsEventEnricher;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.fetch.ignored.HmsIgnoredEventHandler;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class BaseHmsEventSource implements HmsEventSource {
  protected final HmsEventFilter eventFilter;
  protected final List<HmsEventEnricher> eventEnrichers;
  protected final HmsIgnoredEventHandler ignoredEventHandler;

  @Getter
  protected final BlockingQueue<HmsEventStreamRecord> outputQueue;
  @Getter
  protected final BlockingQueue<HmsEventStreamRecord> ignoredEventsQueue;

  private final AtomicBoolean isClosed;
  private volatile Throwable failure;

  protected BaseHmsEventSource(HmsEventFilter eventFilter,
      int eventBatchSize, HmsEventEnricher... eventEnrichers) {
    this(eventFilter, eventBatchSize, Arrays.asList(eventEnrichers));
  }

  protected BaseHmsEventSource(HmsEventFilter eventFilter,
      int eventBatchSize, List<HmsEventEnricher> eventEnrichers) {
    this(eventFilter, eventBatchSize, eventEnrichers, HmsIgnoredEventHandler.noOp());
  }

  protected BaseHmsEventSource(HmsEventFilter eventFilter,
      int eventBatchSize, List<HmsEventEnricher> eventEnrichers,
      HmsIgnoredEventHandler ignoredEventHandler) {
    this.outputQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.ignoredEventsQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.isClosed = new AtomicBoolean(false);
    this.eventFilter = eventFilter;
    this.eventEnrichers = eventEnrichers;
    this.ignoredEventHandler = Optional.ofNullable(ignoredEventHandler)
        .orElseGet(HmsIgnoredEventHandler::noOp);
  }

  protected void sendEvent(HmsEventStreamRecord record) throws InterruptedException {
    if (record instanceof HiveNotificationEvent) {
      sendEvent((HiveNotificationEvent) record);
    } else {
      outputQueue.put(record);
    }
  }

  protected void sendEvent(HiveNotificationEvent event) throws InterruptedException {
    HiveNotificationEvent enrichedEvent = enrichEvent(event);
    if (eventFilter.test(enrichedEvent)) {
      outputQueue.put(enrichedEvent);
      return;
    }

    sendIgnoredEvent(enrichedEvent);
    // records are sent at the place of the ignored event to preserve the events order
    for (HmsEventStreamRecord record : ignoredEventHandler.handle(enrichedEvent, eventFilter)) {
      outputQueue.put(record);
    }
  }

  protected void sendEof() {
    outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
    ignoredEventsQueue.add(HmsEventStreamRecord.endOfStreamRecord());
  }

  protected void sendIgnoredEvent(HmsEventStreamRecord record) throws InterruptedException {
    ignoredEventsQueue.put(record);
  }

  protected void sendEofIfNotClosed() {
    if (!isClosed.get()) {
      sendEof();
    }
  }

  protected HmsEventStream outputStream() {
    return new HmsEventStream(outputQueue, ignoredEventsQueue);
  }

  @Override
  public void close() {
    if (isClosed.compareAndSet(false, true)) {
      closeAction();
    }
  }

  protected abstract void closeAction();

  /**
   * Closes the source due to the error. The end of the stream is sent as for the
   * successful closing, so the consumers should check {@link #getFailure()}
   * after receiving the last record.
   */
  protected void fail(Throwable error) {
    failure = error;
    close();
  }

  public Optional<Throwable> getFailure() {
    return Optional.ofNullable(failure);
  }

  protected boolean isClosed() {
    return isClosed.get();
  }

  private HiveNotificationEvent enrichEvent(HiveNotificationEvent event) {
    return eventEnrichers.stream()
        .reduce(event,
            (currentEvent, enricher) -> enricher.enrich(currentEvent),
            (left, right) -> right);
  }
}
