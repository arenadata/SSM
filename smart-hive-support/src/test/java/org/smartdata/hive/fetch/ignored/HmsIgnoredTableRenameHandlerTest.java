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
package org.smartdata.hive.fetch.ignored;

import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.MessageFactory;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.junit.Test;
import org.smartdata.hive.EntityInfo;
import org.smartdata.hive.fetch.EventOperation;
import org.smartdata.hive.fetch.EventOperationBuilder;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.fetch.filter.HmsEventNameIgnoreFilter;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.NotificationEventFactory.newAlterDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newAlterTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newRenameTableEvent;

public class HmsIgnoredTableRenameHandlerTest {
  private static final HmsEventFilter EVENT_FILTER = new HmsEventNameIgnoreFilter("ignore.*");

  private final HmsIgnoredEventHandler handler = new HmsIgnoredTableRenameHandler(
      new HiveNotificationEventFactory(GzipJSONMessageEncoder.getInstance()));

  @Test
  public void testTableRenamedOutOfScope() throws Exception {
    HiveNotificationEvent event = ssmEvent(
        newRenameTableEvent(7, "hive.db1.tbl1", "hive.ignore.tbl1"));

    List<HmsEventStreamRecord> records = handler.handle(event, EVENT_FILTER);
    assertEquals(1, records.size());
    assertDropTableEvent((HiveNotificationEvent) records.get(0), 7, "db1", "tbl1");
  }

  public static void assertDropTableEvent(
      HiveNotificationEvent event, long externalId, String dbName, String tableName) throws Exception {
    assertEquals(HiveEntity.TABLE.name(), event.getEntityType());
    assertEquals(HiveOperation.DROP.name(), event.getEventType());
    assertEquals(externalId, event.getExternalId());
    assertEquals(dbName, event.getDbName());
    assertEquals(tableName, event.getTableName());
    assertEquals(dbName + "." + tableName, event.getFullName());

    Table droppedTable = MessageFactory.getInstance(event.getMessageFormat())
        .getDeserializer()
        .getDropTableMessage(event.getMessage())
        .getTableObj();
    assertEquals(dbName, droppedTable.getDbName());
    assertEquals(tableName, droppedTable.getTableName());
  }

  @Test
  public void testTableRenamedInsideIgnoredScope() {
    HiveNotificationEvent event = ssmEvent(
        newRenameTableEvent(1, "hive.ignore.tbl1", "hive.ignore.tbl2"));

    assertTrue(handler.handle(event, EVENT_FILTER).isEmpty());
  }

  @Test
  public void testIgnoredTableAlteredWithoutRenaming() {
    HiveNotificationEvent event = ssmEvent(newAlterTableEvent(1, TableType.MANAGED_TABLE,
        new EntityInfo("hive.ignore.tbl1", "/old"),
        new EntityInfo("hive.ignore.tbl1", "/new")));

    assertTrue(handler.handle(event, EVENT_FILTER).isEmpty());
  }

  @Test
  public void testSkipNonTableEvents() {
    HiveNotificationEvent event = ssmEvent(newAlterDbEvent(1,
        new EntityInfo("hive.ignore", "/old"),
        new EntityInfo("hive.ignore", "/new")));

    assertTrue(handler.handle(event, EVENT_FILTER).isEmpty());
  }

  @Test
  public void testSkipInvalidMessage() {
    HiveNotificationEvent event = ssmEvent(
        newRenameTableEvent(1, "hive.db1.tbl1", "hive.ignore.tbl1"))
        .toBuilder()
        .message("invalid")
        .build();

    assertTrue(handler.handle(event, EVENT_FILTER).isEmpty());
  }

  private HiveNotificationEvent ssmEvent(NotificationEvent event) {
    event.setMessageFormat(JSONMessageEncoder.FORMAT);
    EventOperation operation = new EventOperationBuilder().from(event);

    return HiveNotificationEvent.fromMetastoreEvent(event)
        .entityType(operation.getEntity().toString())
        .eventType(operation.getOperation().toString())
        .build();
  }
}
