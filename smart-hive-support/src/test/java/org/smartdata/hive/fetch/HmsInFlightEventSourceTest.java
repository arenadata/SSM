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

import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.api.NotificationEventResponse;
import org.apache.thrift.TException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.smartdata.hive.EntityInfo;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.RetryPolicyFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
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
import static org.smartdata.hive.fetch.HiveEntity.CATALOG;
import static org.smartdata.hive.fetch.HiveEntity.CONNECTOR;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;

public class HmsInFlightEventSourceTest {

  private MetastoreEventsHolder eventsHolder;

  private HmsInFlightEventSource eventFetcher;

  @Before
  public void setUp() throws TException {
    IMetaStoreClient metaStoreClient = mock(IMetaStoreClient.class);
    when(metaStoreClient.getNextNotification(anyLong(), anyInt(), any()))
        .then(invocation -> getEvents(eventsHolder, invocation));

    eventFetcher = HmsInFlightEventSource.builder()
        .metaStoreClient(metaStoreClient)
        // we don't use executor in tests
        .fetchPeriodMs(-1)
        .eventBatchSize(10000)
        .retrySupport(new PolicyBasedRetrySupport(
            RetryPolicyFactory.NO_RETRIES_POLICY, Thread::sleep))
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
        ssmIgnoredEvent(newEvent(15, "default.db.table78", UPDATE_PARTITION_COLUMN_STAT_BATCH)),
        ssmIgnoredEvent(newEvent(19, "default.db_schema", DROP_SCHEMA_VERSION))
    );
    assertEquals(expectedIgnoredRecords, new ArrayList<>(eventFetcher.getIgnoredEventsQueue()));

    assertEquals(Collections.singletonList(0L), eventsHolder.requestedOffsetIds);
    assertEquals(20L, eventFetcher.getLastHandledEventId());
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
        ssmEvent(newEvent(16, "default.db.partitioned_table", ALTER_PARTITION),
            new EventOperation(PARTITION, HiveOperation.ALTER)),
        ssmEvent(newEvent(17, "default.db2", CREATE_FUNCTION),
            new EventOperation(FUNCTION, CREATE)),
        ssmEvent(newEvent(18, "catalog1", DROP_CATALOG),
            new EventOperation(CATALOG, DROP)),
        ssmEvent(newEvent(20, "default.db_conn", CREATE_DATACONNECTOR),
            new EventOperation(CONNECTOR, CREATE))
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
        newEvent(idSeq.getAndIncrement(), "default.db.table78", UPDATE_PARTITION_COLUMN_STAT_BATCH),
        newEvent(idSeq.getAndIncrement(), "default.db.partitioned_table", ALTER_PARTITION),
        newEvent(idSeq.getAndIncrement(), "default.db2", CREATE_FUNCTION),
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
        .fullName(fullResourceName(event))
        .entityType(eventOperation.getEntity().toString())
        .eventType(eventOperation.getOperation() == HiveOperation.UNKNOWN
            ? event.getEventType()
            : eventOperation.getOperation().toString()
        ).build();
  }

  private static class MetastoreEventsHolder {
    private final List<Long> requestedOffsetIds = new ArrayList<>();

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
}