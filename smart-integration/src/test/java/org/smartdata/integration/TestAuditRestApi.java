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
package org.smartdata.integration;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.AuditEventDto;
import org.smartdata.client.generated.model.AuditEventsDto;
import org.smartdata.client.generated.model.AuditOperationDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.AuditApiWrapper;
import org.smartdata.integration.api.RulesApiWrapper;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestAuditRestApi extends IntegrationTestBase {

  private ActionsApiWrapper actionsApiClient;
  private RulesApiWrapper rulesApiClient;
  private AuditApiWrapper auditApiClient;

  @Before
  public void createApi() {
    actionsApiClient = new ActionsApiWrapper();
    rulesApiClient = new RulesApiWrapper();
    auditApiClient = new AuditApiWrapper();
  }

  @Test
  public void testGetEmptyAuditActions() {
    AuditEventsDto auditEvents = auditApiClient.getAuditEvents();

    assertEquals(0, auditEvents.getTotal().longValue());
    assertTrue(auditEvents.getItems().isEmpty());
  }

  @Test
  public void testGetAuditActions() {
    actionsApiClient.submitAction("read -file text1");
    RuleDto rule = rulesApiClient.submitRule(
        "file: path matches \"text1\" | read");

    rulesApiClient.startRule(rule.getId());
    rulesApiClient.stopRule(rule.getId());
    rulesApiClient.deleteRule(rule.getId());

    AuditEventsDto auditEvents = auditApiClient.getAuditEvents();

    assertEquals(5, auditEvents.getTotal().longValue());

    List<AuditOperationDto> expectedOperations = Arrays.asList(
        AuditOperationDto.START,
        AuditOperationDto.CREATE,
        AuditOperationDto.START,
        AuditOperationDto.STOP,
        AuditOperationDto.DELETE
    );

    List<AuditOperationDto> actualOperations = auditEvents.getItems().stream()
        .map(AuditEventDto::getOperation)
        .collect(Collectors.toList());

    assertEquals(expectedOperations, actualOperations);
  }
}
