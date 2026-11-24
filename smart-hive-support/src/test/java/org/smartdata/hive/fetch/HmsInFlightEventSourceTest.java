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

import lombok.Data;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.api.NotificationEventResponse;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.apache.thrift.TException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.smartdata.hive.EntityInfo;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.fetch.filter.HmsEventNameIgnoreFilter;
import org.smartdata.hive.fetch.ignored.HmsIgnoredTableRenameHandler;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_PARTITION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.COMMIT_COMPACTION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.COMMIT_TXN;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_DATACONNECTOR;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_FUNCTION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_CATALOG;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_SCHEMA_VERSION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.UPDATE_PARTITION_COLUMN_STAT_BATCH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.smartdata.hive.NotificationEventFactory.newAlterDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newAlterTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newDropDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newDropTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newEvent;
import static org.smartdata.hive.NotificationEventFactory.newRenameTableEvent;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;
import static org.smartdata.hive.fetch.ignored.HmsIgnoredTableRenameHandlerTest.assertDropTableEvent;

public class HmsInFlightEventSourceTest {

  private MetastoreEventsHolder eventsHolder;

  private HmsInFlightEventSource eventFetcher;

  @Before
  public void setUp() throws TException {
    IMetaStoreClient metaStoreClient = mock(IMetaStoreClient.class);
    when(metaStoreClient.getNextNotification(anyLong(), anyInt(), any()))
        .then(invocation -> getEvents(eventsHolder, invocation));

    eventFetcher = HmsInFlightEventSource.builder()
        .metaStoreClientSupplier(() -> metaStoreClient)
        // we don't use executor in tests
        .fetchPeriodMs(-1)
        .eventBatchSize(10000)
        .eventFilter(new HmsEventNameIgnoreFilter("ignore.*"))
        .eventEnrichers(Collections.emptyList())
        .build();

    eventsHolder = new MetastoreEventsHolder();
  }

  @After
  public void cleanUp() {
    eventFetcher.close();
  }

  @Test
  public void testHandleEvents() {

    List<NotificationEvent> events = getDefaultTestEvents();
    eventsHolder.addEvents(events);

    List<HmsEventStreamRecord> fetchedEvents = getFetchedEvents();
    assertEquals(getExpectedRecords(), fetchedEvents);

    List<HmsEventStreamRecord> expectedIgnoredRecords = Arrays.asList(
        ssmIgnoredEvent(newEvent(8, "default.db.table77", COMMIT_TXN)),
        ssmIgnoredEvent(newEvent(9, "default.db", COMMIT_COMPACTION)),
        ssmIgnoredEvent(newEvent(12, "default.db.table78", "unknown_event_type")),
        ssmEvent(newCreateDbEvent(15, "default.ignored_db", "/ignored_db"), new EventOperation(DATABASE, CREATE)),
        ssmIgnoredEvent(newEvent(16, "default.db.table78", UPDATE_PARTITION_COLUMN_STAT_BATCH)),
        ssmEvent(newCreateDbEvent(17, "default.ignoreddb2", "/ignoreddb2"), new EventOperation(DATABASE, DROP)),
        ssmEvent(newCreateTableEvent(20, "default.ignored_db.tb1", TableType.MANAGED_TABLE,
            "/db/ignored_db/tb1"), new EventOperation(TABLE, CREATE)),
        ssmIgnoredEvent(newEvent(21, "catalog1", DROP_CATALOG)),
        ssmIgnoredEvent(newEvent(22, "default.db_schema", DROP_SCHEMA_VERSION)),
        ssmIgnoredEvent(newEvent(23, "default.db_conn", CREATE_DATACONNECTOR))
    );
    assertEquals(expectedIgnoredRecords, new ArrayList<>(eventFetcher.getIgnoredEventsQueue()));

    assertEquals(Collections.singletonList(0L), eventsHolder.requestedOffsetIds);
    assertEquals(23L, eventFetcher.getLastHandledEventId());
  }

  @Test
  public void testFiniteFetcherStopsOnEndEventWithoutFurtherEvents() {
    eventFetcher = eventFetcher.toFiniteFetcher(2L);
    eventsHolder.addEvents(Arrays.asList(
        newCreateDbEvent(1, "default.db1", "/db1"),
        newCreateDbEvent(2, "default.db2", "/db2")
    ));

    List<HmsEventStreamRecord> expectedRecords = Arrays.asList(
        ssmEvent(newCreateDbEvent(1, "default.db1", "/db1"), new EventOperation(DATABASE, CREATE)),
        ssmEvent(newCreateDbEvent(2, "default.db2", "/db2"), new EventOperation(DATABASE, CREATE)),
        HmsEventStreamRecord.endOfStreamRecord()
    );
    assertEquals(expectedRecords, getFetchedEvents());
    assertTrue(eventFetcher.isClosed());
    assertFalse(eventFetcher.getFailure().isPresent());
  }

  @Test
  public void testFiniteFetcherStopsIfEndEventIsAlreadyHandled() {
    eventFetcher = eventFetcher.toFiniteFetcher(0L);

    assertEquals(Collections.singletonList(HmsEventStreamRecord.endOfStreamRecord()),
        getFetchedEvents());
    assertTrue(eventsHolder.requestedOffsetIds.isEmpty());
  }

  @Test
  public void testFailOnMetastoreError() throws TException {
    IMetaStoreClient failingClient = mock(IMetaStoreClient.class);
    when(failingClient.getNextNotification(anyLong(), anyInt(), any()))
        .thenThrow(new TException("HMS is unavailable"));
    eventFetcher = eventFetcher.toBuilder()
        .metaStoreClientSupplier(() -> failingClient)
        .build();

    assertEquals(Collections.singletonList(HmsEventStreamRecord.endOfStreamRecord()),
        getFetchedEvents());
    assertTrue(eventFetcher.getFailure().isPresent());
  }

  @Test
  public void testStopPollingAfterClosing() throws Exception {
    ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    try {
      eventFetcher = eventFetcher.toBuilder()
          .executor(executor)
          .fetchPeriodMs(10)
          .endEventId(1L)
          .build();
      eventsHolder.addEvents(Collections.singletonList(newCreateDbEvent(1, "default.db1", "/db1")));

      BlockingQueue<HmsEventStreamRecord> events = eventFetcher.eventStreamFrom(0L).getEvents();
      HmsEventStreamRecord record = events.poll(10, TimeUnit.SECONDS);
      while (record != null && !record.isLastRecord()) {
        record = events.poll(10, TimeUnit.SECONDS);
      }
      assertTrue("Fetcher should be closed", record != null && record.isLastRecord());

      int pollsCount = eventsHolder.requestedOffsetIds.size();
      Thread.sleep(200);
      assertEquals(pollsCount, eventsHolder.requestedOffsetIds.size());
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void testSendIgnoredEventHandlerRecordsInPlaceOfIgnoredEvent() {
    HmsEventFilter eventFilter = new HmsEventNameIgnoreFilter("ignore.*");
    List<HmsEventFilter> passedFilters = new ArrayList<>();
    eventFetcher = eventFetcher.toBuilder()
        .eventFilter(eventFilter)
        .ignoredEventHandler((ignoredEvent, filter) -> {
          passedFilters.add(filter);
          return Arrays.asList(new DummyRecord(ignoredEvent.getExternalId(), 1),
              new DummyRecord(ignoredEvent.getExternalId(), 2));
        })
        .build();

    eventsHolder.addEvents(Arrays.asList(
        newCreateDbEvent(1, "default.db1", "/db1"),
        newCreateDbEvent(2, "default.ignored_db", "/ignored_db"),
        newCreateDbEvent(3, "default.db2", "/db2")
    ));

    List<HmsEventStreamRecord> expectedRecords = Arrays.asList(
        ssmEvent(newCreateDbEvent(1, "default.db1", "/db1"), new EventOperation(DATABASE, CREATE)),
        new DummyRecord(2, 1),
        new DummyRecord(2, 2),
        ssmEvent(newCreateDbEvent(3, "default.db2", "/db2"), new EventOperation(DATABASE, CREATE))
    );
    assertEquals(expectedRecords, getFetchedEvents());

    // the ignored event is still sent to the ignored events queue
    assertEquals(
        Collections.singletonList(ssmEvent(newCreateDbEvent(2, "default.ignored_db", "/ignored_db"),
            new EventOperation(DATABASE, CREATE))),
        new ArrayList<>(eventFetcher.getIgnoredEventsQueue()));
    assertEquals(Collections.singletonList(eventFilter), passedFilters);
  }

  @Test
  public void testHandleTableRenamesCrossingScope() throws Exception {
    eventFetcher = eventFetcher.toBuilder()
        .ignoredEventHandler(new HmsIgnoredTableRenameHandler(
            new HiveNotificationEventFactory(GzipJSONMessageEncoder.getInstance())))
        .build();

    eventsHolder.addEvents(Arrays.asList(
        renameTableEvent(1, "default.db.tbl1", "default.ignore.tbl1"),
        renameTableEvent(2, "default.ignore.tbl2", "default.db.tbl2"),
        renameTableEvent(3, "default.ignore.tbl3", "default.ignore.tbl4")
    ));

    List<HmsEventStreamRecord> fetchedRecords = getFetchedEvents();
    assertEquals(2, fetchedRecords.size());
    assertDropTableEvent((HiveNotificationEvent) fetchedRecords.get(0), 1, "db", "tbl1");
    assertEquals(renamedSsmEvent(renameTableEvent(2, "default.ignore.tbl2", "default.db.tbl2")),
        fetchedRecords.get(1));

    List<HmsEventStreamRecord> expectedIgnoredRecords = Arrays.asList(
        renamedSsmEvent(renameTableEvent(1, "default.db.tbl1", "default.ignore.tbl1")),
        renamedSsmEvent(renameTableEvent(3, "default.ignore.tbl3", "default.ignore.tbl4"))
    );
    assertEquals(expectedIgnoredRecords, new ArrayList<>(eventFetcher.getIgnoredEventsQueue()));
  }

  private NotificationEvent renameTableEvent(long id, String nameBefore, String nameAfter) {
    NotificationEvent event = newRenameTableEvent(id, nameBefore, nameAfter);
    event.setMessageFormat(JSONMessageEncoder.FORMAT);
    return event;
  }

  private HiveNotificationEvent renamedSsmEvent(NotificationEvent event) {
    return ssmEvent(event, new EventOperation(TABLE, HiveOperation.ALTER));
  }

  private List<HmsEventStreamRecord> getFetchedEvents() {
    eventFetcher.pollRecordsBatch();
    return new ArrayList<>(eventFetcher.getOutputQueue());
  }

  private NotificationEventResponse getEvents(MetastoreEventsHolder metastoreEventsHolder,
      InvocationOnMock invocation) {
    List<NotificationEvent> events = metastoreEventsHolder.getNextEvents(
        invocation.getArgument(0, Long.class),
        invocation.getArgument(1, Integer.class)
    );
    return new NotificationEventResponse(events);
  }

  private List<HmsEventStreamRecord> getExpectedRecords() {
    return Arrays.asList(
        ssmEvent(newCreateDbEvent(1, "default.newdb", "/newdb"),
            new EventOperation(DATABASE, CREATE)),
        ssmEvent(newCreateTableEvent(2, "default.db.table1", TableType.EXTERNAL_TABLE, "/out/table1"),
            new EventOperation(TABLE, CREATE)),
        ssmEvent(newCreateTableEvent(3, "default.db.table2", TableType.MANAGED_TABLE, "/db/table2"),
            new EventOperation(TABLE, CREATE)),
        ssmEvent(newDropTableEvent(4, "default.db.view1", TableType.VIRTUAL_VIEW, "/doesnt/matter"),
            new EventOperation(TABLE, HiveOperation.DROP)),
        ssmEvent(newAlterDbEvent(5,
                new EntityInfo("default.newdb", "/newdb"),
                new EntityInfo("default.newestdb", "/newestdb")),
            new EventOperation(DATABASE, HiveOperation.ALTER)),
        ssmEvent(newDropTableEvent(6, "default.db.table2", TableType.MANAGED_TABLE, "/db/table2"),
            new EventOperation(TABLE, HiveOperation.DROP)),
        ssmEvent(newAlterDbEvent(7,
                new EntityInfo("default.newestdb", "/newestdb"),
                new EntityInfo("default.newestdb", "/other/location")),
            new EventOperation(DATABASE, HiveOperation.ALTER)),
        ssmEvent(newDropDbEvent(10, "default.newestdb", "/other/location"),
            new EventOperation(DATABASE, HiveOperation.DROP)),
        ssmEvent(newAlterTableEvent(11,
                TableType.EXTERNAL_TABLE,
                new EntityInfo("default.db.table2", "/db/table2"),
                new EntityInfo("default.db.table3", "/db/table3")),
            new EventOperation(TABLE, HiveOperation.ALTER)),
        ssmEvent(newDropTableEvent(13, "default.db.view", TableType.VIRTUAL_VIEW, "/out/view"),
            new EventOperation(TABLE, HiveOperation.DROP)),
        ssmEvent(newAlterTableEvent(14,
                TableType.EXTERNAL_TABLE,
                new EntityInfo("default.db.table3", "/db/table3"),
                new EntityInfo("default.db.table3", "/other/location2")),
            new EventOperation(TABLE, HiveOperation.ALTER)),
        ssmEvent(newEvent(18, "default.db.partitioned_table", ALTER_PARTITION),
            new EventOperation(PARTITION, HiveOperation.ALTER)),
        ssmEvent(newEvent(19, "default.db2", CREATE_FUNCTION),
            new EventOperation(FUNCTION, CREATE))
    );
  }

  private List<NotificationEvent> getDefaultTestEvents() {
    AtomicLong idSeq = new AtomicLong(1L);

    return Arrays.asList(
        newCreateDbEvent(idSeq.getAndIncrement(), "default.newdb", "/newdb"),
        newCreateTableEvent(idSeq.getAndIncrement(), "default.db.table1", TableType.EXTERNAL_TABLE, "/out/table1"),
        newCreateTableEvent(idSeq.getAndIncrement(), "default.db.table2", TableType.MANAGED_TABLE, "/db/table2"),
        newDropTableEvent(idSeq.getAndIncrement(), "default.db.view1", TableType.VIRTUAL_VIEW, "/doesnt/matter"),
        newAlterDbEvent(idSeq.getAndIncrement(),
            new EntityInfo("default.newdb", "/newdb"),
            new EntityInfo("default.newestdb", "/newestdb")),
        newDropTableEvent(idSeq.getAndIncrement(), "default.db.table2", TableType.MANAGED_TABLE, "/db/table2"),
        newAlterDbEvent(idSeq.getAndIncrement(),
            new EntityInfo("default.newestdb", "/newestdb"),
            new EntityInfo("default.newestdb", "/other/location")),
        newEvent(idSeq.getAndIncrement(), "default.db.table77", COMMIT_TXN),
        newEvent(idSeq.getAndIncrement(), "default.db", COMMIT_COMPACTION),
        newDropDbEvent(idSeq.getAndIncrement(), "default.newestdb", "/other/location"),
        newAlterTableEvent(idSeq.getAndIncrement(),
            TableType.EXTERNAL_TABLE,
            new EntityInfo("default.db.table2", "/db/table2"),
            new EntityInfo("default.db.table3", "/db/table3")),
        newEvent(idSeq.getAndIncrement(), "default.db.table78", "unknown_event_type"),
        newDropTableEvent(idSeq.getAndIncrement(), "default.db.view", TableType.VIRTUAL_VIEW, "/out/view"),
        newAlterTableEvent(idSeq.getAndIncrement(),
            TableType.EXTERNAL_TABLE,
            new EntityInfo("default.db.table3", "/db/table3"),
            new EntityInfo("default.db.table3", "/other/location2")),
        newCreateDbEvent(idSeq.getAndIncrement(), "default.ignored_db", "/ignored_db"),
        newEvent(idSeq.getAndIncrement(), "default.db.table78", UPDATE_PARTITION_COLUMN_STAT_BATCH),
        newDropDbEvent(idSeq.getAndIncrement(), "default.ignoreddb2", "/ignoreddb2"),
        newEvent(idSeq.getAndIncrement(), "default.db.partitioned_table", ALTER_PARTITION),
        newEvent(idSeq.getAndIncrement(), "default.db2", CREATE_FUNCTION),
        newCreateTableEvent(idSeq.getAndIncrement(), "default.ignored_db.tb1", TableType.MANAGED_TABLE,
            "/db/ignored_db/tb1"),
        newEvent(idSeq.getAndIncrement(), "catalog1", DROP_CATALOG),
        newEvent(idSeq.getAndIncrement(), "default.db_schema", DROP_SCHEMA_VERSION),
        newEvent(idSeq.getAndIncrement(), "default.db_conn", CREATE_DATACONNECTOR)
    );
  }

  private HiveNotificationEvent ssmIgnoredEvent(NotificationEvent event) {
    return ssmEvent(event, EventOperation.unknown());
  }

  private HiveNotificationEvent ssmEvent(NotificationEvent event, EventOperation eventOperation) {
    return HiveNotificationEvent.fromMetastoreEvent(event)
        .entityType(eventOperation.getEntity().toString())
        .eventType(eventOperation.getOperation() == HiveOperation.UNKNOWN
            ? event.getEventType()
            : eventOperation.getOperation().toString()
        ).build();
  }

  private static class MetastoreEventsHolder {
    private final List<Long> requestedOffsetIds = Collections.synchronizedList(new ArrayList<>());

    private final PriorityQueue<NotificationEvent> eventQueue = new PriorityQueue<>(
        Comparator.comparingLong(NotificationEvent::getEventId)
    );

    public void addEvents(Collection<NotificationEvent> events) {
      eventQueue.addAll(events);
    }

    public List<NotificationEvent> getNextEvents(long offsetId, int batchSize) {
      requestedOffsetIds.add(offsetId);
      return IntStream.range(0, eventQueue.size())
          .mapToObj(i -> eventQueue.poll())
          .filter(Objects::nonNull)
          .filter(event -> event.getEventId() > offsetId)
          .limit(batchSize)
          .collect(Collectors.toList());
    }
  }

  @Data
  private static class DummyRecord implements HmsEventStreamRecord {
    private final long ignoredEventId;
    private final int index;
  }
}
