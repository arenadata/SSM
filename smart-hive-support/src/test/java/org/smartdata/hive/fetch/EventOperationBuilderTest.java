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

import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ABORT_TXN;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ACID_WRITE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_CHECKCONSTRAINT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_DEFAULTCONSTRAINT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_FOREIGNKEY;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_NOTNULLCONSTRAINT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_PARTITION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_PRIMARYKEY;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_SCHEMA_VERSION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ADD_UNIQUECONSTRAINT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALLOC_WRITE_ID;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_CATALOG;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_DATACONNECTOR;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_ISCHEMA;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_PARTITION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_SCHEMA_VERSION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_TABLE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.BATCH_ACID_WRITE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.COMMIT_COMPACTION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.COMMIT_TXN;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_CATALOG;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_DATACONNECTOR;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_FUNCTION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_ISCHEMA;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_TABLE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DELETE_PARTITION_COLUMN_STAT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DELETE_TABLE_COLUMN_STAT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_CATALOG;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_CONSTRAINT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_DATACONNECTOR;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_FUNCTION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_ISCHEMA;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_PARTITION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_SCHEMA_VERSION;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_TABLE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.INSERT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.OPEN_TXN;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.RELOAD;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.UPDATE_PARTITION_COLUMN_STAT;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.UPDATE_PARTITION_COLUMN_STAT_BATCH;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.UPDATE_TABLE_COLUMN_STAT;
import static org.junit.Assert.assertEquals;
import static org.smartdata.hive.fetch.HiveEntity.CATALOG;
import static org.smartdata.hive.fetch.HiveEntity.CONNECTOR;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveOperation.ALTER;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;

@RunWith(Parameterized.class)
public class EventOperationBuilderTest {

  @Parameterized.Parameter
  public EventMessage.EventType inputEvent;
  @Parameterized.Parameter(1)
  public EventOperation expectedOperation;

  private EventOperationBuilder builder;

  @Before
  public void createApi() {
    builder = new EventOperationBuilder();
  }

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        // Database operations
        {CREATE_DATABASE, new EventOperation(DATABASE, CREATE)},
        {DROP_DATABASE, new EventOperation(DATABASE, DROP)},
        {ALTER_DATABASE, new EventOperation(DATABASE, ALTER)},

        // Table operations
        {CREATE_TABLE, new EventOperation(TABLE, CREATE)},
        {DROP_TABLE, new EventOperation(TABLE, DROP)},
        {ALTER_TABLE, new EventOperation(TABLE, ALTER)},
        {ADD_PRIMARYKEY, new EventOperation(TABLE, ALTER)},
        {ADD_FOREIGNKEY, new EventOperation(TABLE, ALTER)},
        {ADD_UNIQUECONSTRAINT, new EventOperation(TABLE, ALTER)},
        {ADD_NOTNULLCONSTRAINT, new EventOperation(TABLE, ALTER)},
        {ADD_DEFAULTCONSTRAINT, new EventOperation(TABLE, ALTER)},
        {ADD_CHECKCONSTRAINT, new EventOperation(TABLE, ALTER)},
        {DROP_CONSTRAINT, new EventOperation(TABLE, ALTER)},

        // Partition operations
        {ADD_PARTITION, new EventOperation(PARTITION, CREATE)},
        {DROP_PARTITION, new EventOperation(PARTITION, DROP)},
        {ALTER_PARTITION, new EventOperation(PARTITION, ALTER)},

        // Function operations
        {CREATE_FUNCTION, new EventOperation(FUNCTION, CREATE)},
        {DROP_FUNCTION, new EventOperation(FUNCTION, DROP)},

        // Catalog operations
        {CREATE_CATALOG, new EventOperation(CATALOG, CREATE)},
        {DROP_CATALOG, new EventOperation(CATALOG, DROP)},
        {ALTER_CATALOG, new EventOperation(CATALOG, ALTER)},

        // DataConnector operations
        {CREATE_DATACONNECTOR, new EventOperation(CONNECTOR, CREATE)},
        {DROP_DATACONNECTOR, new EventOperation(CONNECTOR, DROP)},
        {ALTER_DATACONNECTOR, new EventOperation(CONNECTOR, ALTER)},

        // Ignored operations
        {INSERT, EventOperation.ignored()},
        {ALLOC_WRITE_ID, EventOperation.ignored()},
        {CREATE_ISCHEMA, EventOperation.ignored()},
        {ALTER_ISCHEMA, EventOperation.ignored()},
        {DROP_ISCHEMA, EventOperation.ignored()},
        {ADD_SCHEMA_VERSION, EventOperation.ignored()},
        {ALTER_SCHEMA_VERSION, EventOperation.ignored()},
        {DROP_SCHEMA_VERSION, EventOperation.ignored()},
        {OPEN_TXN, EventOperation.ignored()},
        {COMMIT_TXN, EventOperation.ignored()},
        {ABORT_TXN, EventOperation.ignored()},
        {ACID_WRITE, EventOperation.ignored()},
        {BATCH_ACID_WRITE, EventOperation.ignored()},
        {UPDATE_TABLE_COLUMN_STAT, EventOperation.ignored()},
        {DELETE_TABLE_COLUMN_STAT, EventOperation.ignored()},
        {UPDATE_PARTITION_COLUMN_STAT, EventOperation.ignored()},
        {UPDATE_PARTITION_COLUMN_STAT_BATCH, EventOperation.ignored()},
        {DELETE_PARTITION_COLUMN_STAT, EventOperation.ignored()},
        {COMMIT_COMPACTION, EventOperation.ignored()},
        {RELOAD, EventOperation.ignored()}
    });
  }

  @Test
  public void testToEventOperationMapping() {
    EventOperation actualOperation = builder.toEventOperation(inputEvent);
    assertEquals(expectedOperation, actualOperation);
  }

  @Test
  public void testFromValidEvent() {
    NotificationEvent event = new NotificationEvent(1L, 1, "CREATE_TABLE", "message");
    EventOperation expected = new EventOperation(TABLE, CREATE);
    assertEquals(expected, builder.from(event));
  }

  @Test
  public void testFromEventWithInvalidType() {
    NotificationEvent event = new NotificationEvent(1L, 1, "SOME_INVALID_EVENT_TYPE", "message");
    assertEquals(EventOperation.unknown(), builder.from(event));
  }

  @Test
  public void testFromEventWithNullType() {
    NotificationEvent event = new NotificationEvent(1L, 1, null, "message");
    assertEquals(EventOperation.unknown(), builder.from(event));
  }
}