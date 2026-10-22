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
package org.smartdata.server.engine.replication.rule;

import org.junit.Test;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.PreserveAttribute;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationScheduleType;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.smartdata.server.engine.replication.rule.RuleAssertions.assertRules;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.targetCluster;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.timePoint;

public class TestDataRuleGenerator {
  private final DataRuleGenerator generator = new DataRuleGenerator();

  @Test
  public void testReplicationDisabled() {
    RuleGenerationResult result = generator.generate(request("/warehouse/db1.db/")
        .settings(DataReplicationSettings.builder().enabled(false).build())
        .build());

    assertEquals(RuleGenerationResult.empty(), result);
  }

  @Test
  public void testRulePerRoot() throws Exception {
    RuleGenerationResult result = generator.generate(
        request("/warehouse/db1.db/", "/external/clients").build());

    // roots are sorted and normalized
    assertRules(result,
        "file: path matches \"/external/clients/*\" "
            + "| sync -dest hdfs://ns2/external/clients/ -preserve owner,group,permissions",
        "file: path matches \"/warehouse/db1.db/*\" "
            + "| sync -dest hdfs://ns2/warehouse/db1.db/ -preserve owner,group,permissions");
    assertEquals(List.of("/external/clients/", "/warehouse/db1.db/"),
        result.getRules().stream()
            .map(GeneratedRule::getSource)
            .collect(Collectors.toList()));
    assertEquals(ReplicationRuleType.DATA, result.getRules().get(0).getType());
  }

  @Test
  public void testNoRoots() throws Exception {
    assertRules(generator.generate(request().build()));
  }

  @Test
  public void testReplicationSettings() throws Exception {
    RuleGenerationResult result = generator.generate(request("/warehouse/db2.db/")
        .settings(DataReplicationSettings.builder()
            .enabled(true)
            .preservedAttributes(EnumSet.of(
                PreserveAttribute.MODIFICATION_TIME, PreserveAttribute.OWNER))
            .events(EnumSet.of(FileDiffType.DELETE, FileDiffType.CREATE))
            .build())
        .schedule(ReplicationSchedule.builder()
            .type(ReplicationScheduleType.EVERY)
            .intervalSeconds(3600L)
            .startTime(timePoint("2026-10-21 10:00:00"))
            .build())
        .targetCluster(targetCluster().hdfsUri("hdfs://ns2/backup/").build())
        .build());

    assertRules(result,
        "file: every 3600s from \"2026-10-21 10:00:00\" | path matches \"/warehouse/db2.db/*\" "
            + "| sync -dest hdfs://ns2/backup/warehouse/db2.db/ "
            + "-preserve owner,modification-time -include CREATE,DELETE");
  }

  @Test
  public void testAllEventsAreNotRestricted() throws Exception {
    for (Set<FileDiffType> events : List.of(
        Set.<FileDiffType>of(), EnumSet.copyOf(FileDiffType.FILTERABLE_DIFF_TYPES))) {
      RuleGenerationResult result = generator.generate(request("/warehouse/db2.db/")
          .settings(DataReplicationSettings.builder().enabled(true).events(events).build())
          .build());

      assertRules(result, "file: path matches \"/warehouse/db2.db/*\" "
          + "| sync -dest hdfs://ns2/warehouse/db2.db/ -preserve owner,group,permissions");
    }
  }

  @Test
  public void testNoPreservedAttributes() throws Exception {
    RuleGenerationResult result = generator.generate(request("/warehouse/db2.db/")
        .settings(DataReplicationSettings.builder()
            .enabled(true)
            .preservedAttributes(Set.of())
            .build())
        .build());

    assertRules(result, "file: path matches \"/warehouse/db2.db/*\" "
        + "| sync -dest hdfs://ns2/warehouse/db2.db/ -preserve none");
  }

  private static DataRuleGenerationRequest.Builder request(String... roots) {
    return DataRuleGenerationRequest.builder()
        .roots(List.of(roots))
        .settings(DataReplicationSettings.builder().enabled(true).build())
        .schedule(ReplicationSchedule.eventDriven())
        .targetCluster(targetCluster().build());
  }
}
