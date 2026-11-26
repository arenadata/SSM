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
package org.smartdata.hive.catalog;

import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.handler.HmsEventHandler;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.HiveEntityFactory.buildDb;
import static org.smartdata.hive.HiveEntityFactory.buildTable;
import static org.smartdata.retry.RetryPolicyFactory.NO_RETRIES_POLICY;

public class HiveCatalogEventsReplayerTest {
  private final HiveNotificationEventFactory eventFactory =
      new HiveNotificationEventFactory(GzipJSONMessageEncoder.getInstance());

  private InMemoryHmsEventDao eventDao;
  private CatalogHmsEventHandlerTest.InMemoryHiveCatalogDao catalogDao;
  private InMemoryCatalogStateDao catalogStateDao;
  private MockTransactionManager transactionManager;

  @Before
  public void setUp() {
    eventDao = new InMemoryHmsEventDao();
    catalogDao = new CatalogHmsEventHandlerTest.InMemoryHiveCatalogDao();
    catalogStateDao = new InMemoryCatalogStateDao();
    transactionManager = new MockTransactionManager();
  }

  @Test
  public void testFillCatalogWithStoredEvents() throws Exception {
    catalogDao.upsertTable(HiveTableInfo.builder()
        .dbName("db1").name("stale").location("/stale").build());
    Table table1 = buildTable("hive.db1.tbl1", TableType.MANAGED_TABLE, "/db1/tbl1");
    Table table2 = buildTable("hive.db1.tbl2", TableType.MANAGED_TABLE, "/db1/tbl2");
    eventDao.insert(
        eventFactory.createDbEvent(buildDb("hive.db1", "/db1"), 10),
        eventFactory.createTableEvent(table1, 10),
        eventFactory.createTableEvent(table2, 11),
        eventFactory.createDropTableEvent(table1, 12)
    );

    replayer(catalogHandler(), 2).replay();

    assertTrue(catalogStateDao.isInitialized());
    assertEquals(Collections.singleton("db1"), catalogDao.databases.keySet());
    // previous catalog state is removed
    assertEquals(Collections.singleton("db1.tbl2"), catalogDao.tables.keySet());
    assertEquals(1, transactionManager.committed);
  }

  @Test
  public void testReplayEventsInStoringOrder() throws Exception {
    eventDao.insert(event(5), event(3), event(7), event(4), event(6));
    List<Long> handledExternalIds = new ArrayList<>();

    replayer(record -> handledExternalIds.add(
        ((HiveNotificationEvent) record).getExternalId()), 2).replay();

    assertEquals(Arrays.asList(5L, 3L, 7L, 4L, 6L), handledExternalIds);
  }

  @Test
  public void testReplayWithoutStoredEvents() throws Exception {
    replayer(catalogHandler(), 10).replay();

    assertTrue(catalogStateDao.isInitialized());
  }

  @Test
  public void testRollbackOnCatalogUpdateFailure() {
    eventDao.insert(event(1));
    HiveCatalogEventsReplayer replayer = replayer(record -> {
      throw new IllegalArgumentException("Catalog update failure");
    }, 10);

    assertThrows(IllegalArgumentException.class, replayer::replay);

    assertFalse(catalogStateDao.isInitialized());
    assertEquals(0, transactionManager.committed);
    assertEquals(1, transactionManager.rolledBack);
  }

  private HiveCatalogEventsReplayer replayer(
      HmsEventHandler catalogHandler, int batchSize) {
    return HiveCatalogEventsReplayer.builder()
        .eventDao(eventDao)
        .catalogHandler(catalogHandler)
        .catalogDao(catalogDao)
        .catalogStateDao(catalogStateDao)
        .transactionManager(transactionManager)
        .batchSize(batchSize)
        .build();
  }

  private CatalogHmsEventHandler catalogHandler() {
    return new CatalogHmsEventHandler(catalogDao,
        new PolicyBasedRetrySupport(NO_RETRIES_POLICY, ignore -> {}));
  }

  private static HiveNotificationEvent event(long externalId) {
    return HiveNotificationEvent.builder()
        .externalId(externalId)
        .fullName("db.tbl")
        .build();
  }

  private static class InMemoryHmsEventDao implements HmsEventDao {
    private final NavigableMap<Long, HiveNotificationEvent> events = new TreeMap<>();

    void insert(HiveNotificationEvent... newEvents) {
      for (HiveNotificationEvent event : newEvents) {
        insert(event);
      }
    }

    @Override
    public void insert(HiveNotificationEvent event) {
      long id = events.size() + 1L;
      events.put(id, event.toBuilder().id(id).build());
    }

    @Override
    public void insertIfNotPresent(HiveNotificationEvent event) {
      throw new UnsupportedOperationException();
    }

    @Override
    public HiveNotificationEvent get(long eventId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteAll() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteEventsFor(String fullName) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Optional<Long> getLatestExternalEventId() {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<HiveNotificationEvent> getEventsAfter(long eventId, int limit) {
      return events.tailMap(eventId, false)
          .values()
          .stream()
          .limit(limit)
          .collect(Collectors.toList());
    }

    @Override
    public <T> T execute(TransactionCallback<T> action) {
      return action.doInTransaction(new SimpleTransactionStatus());
    }
  }

  private static class InMemoryCatalogStateDao implements HiveCatalogStateDao {
    private boolean initialized;

    @Override
    public boolean isInitialized() {
      return initialized;
    }

    @Override
    public void markInitialized() {
      initialized = true;
    }
  }

  private static class MockTransactionManager implements PlatformTransactionManager {
    private int committed;
    private int rolledBack;

    @Override
    public TransactionStatus getTransaction(TransactionDefinition definition) {
      return new SimpleTransactionStatus();
    }

    @Override
    public void commit(TransactionStatus status) {
      committed++;
    }

    @Override
    public void rollback(TransactionStatus status) {
      rolledBack++;
    }
  }
}
