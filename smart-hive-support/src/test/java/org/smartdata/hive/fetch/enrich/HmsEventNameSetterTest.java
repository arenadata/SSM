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
package org.smartdata.hive.fetch.enrich;

import org.apache.hadoop.hive.metastore.messaging.CreateDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.DropFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageBuilder;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.smartdata.hive.HiveEntityFactory.buildDb;
import static org.smartdata.hive.HiveEntityFactory.buildFunction;

public class HmsEventNameSetterTest {

  private HmsEventNameSetter eventNameSetter;
  private MessageEncoder messageEncoder;

  @Before
  public void setUp() {
    this.messageEncoder = JSONMessageEncoder.getInstance();
    this.eventNameSetter = new HmsEventNameSetter(messageEncoder);
  }

  @Test
  public void testUpdateNameInCreateFunctionEvent() {
    CreateFunctionMessage message = MessageBuilder.getInstance()
        .buildCreateFunctionMessage(buildFunction("hive.db.function1"));
    testUpdateNameInFunctionEvent(message, HiveOperation.CREATE, "db.function1");
  }

  @Test
  public void testUpdateNameInDropFunctionEvent() {
    DropFunctionMessage message = MessageBuilder.getInstance()
        .buildDropFunctionMessage(buildFunction("hive.db.function2"));
    testUpdateNameInFunctionEvent(message, HiveOperation.DROP, "db.function2");
  }

  @Test
  public void testReturnOldNameByDefault() {
    CreateDatabaseMessage message = MessageBuilder.getInstance()
        .buildCreateDatabaseMessage(buildDb("hive.db", "/loc"));

    String serializedMessage = messageEncoder.getSerializer().serialize(message);

    HiveNotificationEvent functionEvent = HiveNotificationEvent
        .builder()
        .fullName("db")
        .entityType(HiveEntity.DATABASE.name())
        .eventType(HiveOperation.CREATE.name())
        .message(serializedMessage)
        .messageFormat(messageEncoder.getMessageFormat())
        .build();
    HiveNotificationEvent enrichedEvent = eventNameSetter.enrich(functionEvent);
    assertEquals("db", enrichedEvent.getFullName());
  }

  @Test
  public void testReturnOldNameForEmptyEvent() {
    HiveNotificationEvent functionEvent = HiveNotificationEvent.builder().build();
    HiveNotificationEvent enrichedEvent = eventNameSetter.enrich(functionEvent);
    assertNull(enrichedEvent.getFullName());
  }

  private void testUpdateNameInFunctionEvent(EventMessage message, HiveOperation operation, String expectedName) {
    String serializedMessage = messageEncoder.getSerializer().serialize(message);

    HiveNotificationEvent functionEvent = HiveNotificationEvent
        .builder()
        .fullName("db")
        .entityType(HiveEntity.FUNCTION.name())
        .eventType(operation.name())
        .message(serializedMessage)
        .messageFormat(messageEncoder.getMessageFormat())
        .build();
    HiveNotificationEvent enrichedEvent = eventNameSetter.enrich(functionEvent);
    assertEquals(expectedName, enrichedEvent.getFullName());
  }
}
