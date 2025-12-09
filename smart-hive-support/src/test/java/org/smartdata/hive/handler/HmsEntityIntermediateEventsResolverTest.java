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

package org.smartdata.hive.handler;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class HmsEntityIntermediateEventsResolverTest {
  private static final String TEST_ENTITY_TYPE = "mock";

  private MockResolver resolver;

  @Before
  public void setUp() {
    resolver = new MockResolver();
  }

  @Test
  public void testResolve() {
    List<HiveNotificationEvent> events = Arrays.asList(
        alter(1L, "old", "new"),
        create(2L, "a"),
        create(3L, "b"),
        drop(4L, "a"),
        drop(5L, "unknown"),
        alter(6L, "b", "a")
    );

    List<HiveNotificationEvent> expectedEventsToCreate = Arrays.asList(
        create(1L, "new"),
        create(6L, "a")
    );

    Set<String> expectedEntitiesToDelete = ImmutableSet.of(
        "old",
        "a",
        "unknown",
        "b"
    );

    events.forEach(resolver::handle);

    List<HiveNotificationEvent> actualEventsToCreate = resolver.getEntitiesToCreate()
        .values()
        .stream()
        .sorted(Comparator.comparingLong(HiveNotificationEvent::getExternalId))
        .collect(Collectors.toList());

    assertEquals(expectedEventsToCreate, actualEventsToCreate);
    assertEquals(expectedEntitiesToDelete, resolver.getEntityNamesToDelete());
  }

  private HiveNotificationEvent create(long id, String entityName) {
    return baseEvent(id, entityName)
        .eventType(HiveOperation.CREATE.toString())
        .build();
  }

  private HiveNotificationEvent drop(long id, String entityName) {
    return baseEvent(id, entityName)
        .eventType(HiveOperation.DROP.toString())
        .build();
  }

  private HiveNotificationEvent alter(long id, String oldName, String newName) {
    return baseEvent(id, oldName)
        .eventType(HiveOperation.ALTER.toString())
        .message(newName)
        .build();
  }

  private HiveNotificationEvent.Builder baseEvent(long id, String entityName) {
    return HiveNotificationEvent.builder()
        .id(id)
        .externalId(id)
        .fullName(entityName)
        .entityType(TEST_ENTITY_TYPE);
  }

  private static class MockResolver extends HmsEntityIntermediateEventsResolver {

    @Override
    protected HiveNotificationEvent getUpdatedEvent(HiveNotificationEvent event) {
      return event.toBuilder()
          .eventType(HiveOperation.CREATE.toString())
          .fullName(event.getMessage())
          .message(null)
          .build();
    }
  }
}