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

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Value;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.CurrentNotificationEventId;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.snapshot.HmsSnapshotEventSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.INTERMEDIATE_EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.SNAPSHOT_STARTED;
import static org.smartdata.hive.fetch.composite.NewHiveSourceStateRecord.newStateRecord;

public class CompositeHmsEventSourceTest {
  @Test
  public void fetchWithIntermediateEvents() throws Exception {
    CurrentNotificationEventId eventIdBeforeSnapshot = new CurrentNotificationEventId();
    eventIdBeforeSnapshot.setEventId(3L);
    CurrentNotificationEventId eventIdAfterSnapshot = new CurrentNotificationEventId();
    eventIdAfterSnapshot.setEventId(7L);

    List<HmsEventStreamRecord> snapshotRecords = Arrays.asList(
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3)
    );

    List<HmsEventStreamRecord> eventRecords = Arrays.asList(
        new DummyRecord(4),
        new IgnoredDummyRecord(5),
        new DummyRecord(7),
        new IgnoredDummyRecord(6),
        new IgnoredDummyRecord(8),
        new DummyRecord(9)
    );

    List<HmsEventStreamRecord> expectedRecords = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        newStateRecord(INTERMEDIATE_EVENTS_STARTED),
        new DummyRecord(4),
        new DummyRecord(7),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(9),
        HmsEventStreamRecord.END_OF_STREAM_RECORD
    );

    testMultiPhaseFetch(
        eventIdBeforeSnapshot,
        eventIdAfterSnapshot,
        snapshotRecords,
        eventRecords,
        expectedRecords
    );
  }

  @Test
  public void fetchWithoutIntermediateEvents() throws Exception {
    CurrentNotificationEventId eventIdBeforeSnapshot = new CurrentNotificationEventId();
    eventIdBeforeSnapshot.setEventId(3L);

    List<HmsEventStreamRecord> snapshotRecords = Arrays.asList(
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3)
    );

    List<HmsEventStreamRecord> eventRecords = Arrays.asList(
        new DummyRecord(4),
        new DummyRecord(5),
        new IgnoredDummyRecord(44),
        new DummyRecord(6),
        new IgnoredDummyRecord(45),
        new IgnoredDummyRecord(55)
    );

    List<HmsEventStreamRecord> expectedRecords = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(4),
        new DummyRecord(5),
        new DummyRecord(6),
        HmsEventStreamRecord.END_OF_STREAM_RECORD
    );

    testMultiPhaseFetch(
        eventIdBeforeSnapshot,
        eventIdBeforeSnapshot,
        snapshotRecords,
        eventRecords,
        expectedRecords
    );
  }

  @Test
  public void fetchDirectlyFromEventFetcher() {
    List<HmsEventStreamRecord> eventRecords = Arrays.asList(
        new DummyRecord(3),
        new DummyRecord(4),
        new DummyRecord(5),
        new DummyRecord(6)
    );

    List<HmsEventStreamRecord> expectedRecords = Arrays.asList(
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(4),
        new DummyRecord(5),
        new DummyRecord(6),
        HmsEventStreamRecord.END_OF_STREAM_RECORD
    );

    testSinglePhaseFetch(
        3L,
        eventRecords,
        expectedRecords
    );
  }

  private void testMultiPhaseFetch(
      CurrentNotificationEventId eventIdBeforeSnapshot,
      CurrentNotificationEventId eventIdAfterSnapshot,
      List<HmsEventStreamRecord> snapshotRecords,
      List<HmsEventStreamRecord> eventRecords,
      List<HmsEventStreamRecord> expectedRecords
  ) throws Exception {
    IMetaStoreClient metaStoreClient = mock(IMetaStoreClient.class);
    when(metaStoreClient.getCurrentNotificationEventId())
        .thenReturn(eventIdBeforeSnapshot, eventIdAfterSnapshot);

    try (CompositeHmsEventSource fetcher = initFetcher(metaStoreClient, snapshotRecords, eventRecords)) {
      fetcher.multiPhaseFetch();
      assertEquals(expectedRecords, new ArrayList<>(fetcher.getOutputQueue()));
    }
  }

  private void testSinglePhaseFetch(
      long fromEventId,
      List<HmsEventStreamRecord> eventRecords,
      List<HmsEventStreamRecord> expectedRecords) {
    IMetaStoreClient metaStoreClient = mock(IMetaStoreClient.class);

    try (CompositeHmsEventSource fetcher = initFetcher(metaStoreClient, Collections.emptyList(),
        eventRecords)) {
      fetcher.fetchMetastoreEventsDirectly(fromEventId);
      assertEquals(expectedRecords, new ArrayList<>(fetcher.getOutputQueue()));
    }
  }

  private CompositeHmsEventSource initFetcher(
      IMetaStoreClient metaStoreClient,
      List<HmsEventStreamRecord> snapshotRecords,
      List<HmsEventStreamRecord> eventRecords) {

    return CompositeHmsEventSource.builder()
        .metaStoreClientSupplier(() -> metaStoreClient)
        .snapshotFetcher(new MockSnapshotFetcher(snapshotRecords))
        .eventFetcher(new MockEventFetcher(eventRecords))
        .executor(Executors.newFixedThreadPool(2))
        .eventBatchSize(1000)
        .build();
  }

  private static class MockSnapshotFetcher extends HmsSnapshotEventSource {

    private final BlockingQueue<HmsEventStreamRecord> records;

    public MockSnapshotFetcher(List<HmsEventStreamRecord> records) {
      super(null, Executors.newSingleThreadExecutor(),
          HmsEventFilter.noOp(), null, new HiveSmartConf(new SmartConf()));
      this.records = new ArrayBlockingQueue<>(records.size() + 1);
      this.records.addAll(records);
      this.records.add(HmsEventStreamRecord.endOfStreamRecord());
    }

    @Override
    public HmsEventStream eventStream() {
      return HmsEventStream.withoutIgnoredEvents(records);
    }

    @Override
    public HmsEventStream eventStreamFrom(long eventId) {
      return HmsEventStream.withoutIgnoredEvents(records);
    }
  }

  private static class MockEventFetcher extends HmsInFlightEventSource {
    private final BlockingQueue<HmsEventStreamRecord> records;

    public MockEventFetcher(List<HmsEventStreamRecord> records) {
      this(new ArrayBlockingQueue<>(records.size() + 1), null);
      Map<Boolean, List<HmsEventStreamRecord>> recordsByIgnore = records.stream()
          .collect(Collectors.partitioningBy(IgnoredDummyRecord.class::isInstance));

      this.records.addAll(recordsByIgnore.get(false));
      this.records.add(HmsEventStreamRecord.endOfStreamRecord());
    }

    private MockEventFetcher(
        BlockingQueue<HmsEventStreamRecord> records,
        Long endEventId) {
      super(null, null, HmsEventFilter.noOp(), 0, 1, endEventId, Collections.emptyList());
      this.records = records;
    }

    @Override
    public HmsEventStream eventStream() {
      return HmsEventStream.withoutIgnoredEvents(records);
    }

    @Override
    public HmsEventStream eventStreamFrom(long eventId) {
      return HmsEventStream.withoutIgnoredEvents(
          filterById(records, eventId)
      );
    }

    @Override
    public HmsInFlightEventSource toFiniteFetcher(long endEventId) {
      return new MockEventFetcher(records, endEventId);
    }

    @Override
    public void close() {
      // do nothing
    }

    private BlockingQueue<HmsEventStreamRecord> filterById(
        BlockingQueue<HmsEventStreamRecord> records,
        long startId) {
      BlockingQueue<HmsEventStreamRecord> queue = records.stream()
          .filter(DummyRecord.class::isInstance)
          .map(DummyRecord.class::cast)
          .filter(record -> record.id > startId)
          .filter(record -> getEndEventId() == null || record.id <= getEndEventId())
          .collect(Collectors.toCollection(() -> new ArrayBlockingQueue<>(records.size() + 1)));
      queue.add(HmsEventStreamRecord.endOfStreamRecord());
      return queue;
    }
  }

  @Data
  private static class DummyRecord implements HmsEventStreamRecord {
    private final int id;
  }

  @Value
  @EqualsAndHashCode(callSuper = true)
  private static class IgnoredDummyRecord extends DummyRecord {
    public IgnoredDummyRecord(int id) {
      super(id);
    }
  }
}