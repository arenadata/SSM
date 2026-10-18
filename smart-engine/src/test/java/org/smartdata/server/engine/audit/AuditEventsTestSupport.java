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
package org.smartdata.server.engine.audit;

import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.audit.UserActivityObject;
import org.smartdata.model.request.AuditSearchRequest;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

class AuditEventsTestSupport {
  private final AuditService auditService;

  AuditEventsTestSupport(AuditService auditService) {
    this.auditService = auditService;
  }

  /**
   * Asserts the audit events of the object type in the "objectId operation result" format,
   * ordered by the event id.
   */
  void assertEvents(UserActivityObject objectType, String... expectedEvents) throws Exception {
    List<UserActivityEvent> events = auditService.search(AuditSearchRequest.builder()
        .objectTypes(Collections.singletonList(objectType))
        .build());

    List<String> actualEvents = events.stream()
        .sorted(Comparator.comparing(UserActivityEvent::getId))
        .peek(event -> assertEquals("anonymous", event.getUsername()))
        .map(event -> event.getObjectId() + " " + event.getOperation() + " " + event.getResult())
        .collect(Collectors.toList());
    assertEquals(List.of(expectedEvents), actualEvents);
  }
}
