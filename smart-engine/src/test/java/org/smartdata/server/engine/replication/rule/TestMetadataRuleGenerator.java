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
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationScheduleType;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.smartdata.server.engine.replication.rule.RuleAssertions.assertRules;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.SOURCE_NAMESERVICE;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.databases;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.tables;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.targetCluster;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.timePoint;

public class TestMetadataRuleGenerator {
  private final MetadataRuleGenerator generator = new MetadataRuleGenerator();

  @Test
  public void testReplicationDisabled() {
    RuleGenerationResult result = generator.generate(request(databases("db1"))
        .settings(MetadataReplicationSettings.builder().enabled(false).build())
        .build());

    assertEquals(RuleGenerationResult.empty(), result);
  }

  @Test
  public void testReplicateWholeDatabases() throws Exception {
    RuleGenerationResult result = generator.generate(request(databases("db2", "db1")).build());

    assertRules(result,
        "hms: name matches \"db1.*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"",
        "hms: name matches \"db2.*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"");
    assertEquals(List.of("db1", "db2"), sources(result));
    assertEquals(ReplicationRuleType.METADATA, result.getRules().get(0).getType());
  }

  @Test
  public void testReplicateSelectedTables() throws Exception {
    ReplicationSource source = tables(List.of("db1", "db2", "db3"),
        SourceTable.of("db1", "sales"),
        SourceTable.of("db2", "orders"),
        SourceTable.of("db2", "clients"));

    RuleGenerationResult result = generator.generate(request(source).build());

    // database without selected tables is replicated entirely
    assertRules(result,
        "hms: name matches \"db1.sales\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"",
        "hms: name matches \"db2.clients\" or name matches \"db2.orders\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"",
        "hms: name matches \"db3.*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"");
  }

  @Test
  public void testReplicationSettings() throws Exception {
    RuleGenerationResult result = generator.generate(request(databases("db1"))
        .settings(settings()
            .cascade(true)
            .events(EnumSet.of(HiveOperation.DROP, HiveOperation.CREATE))
            .build())
        .schedule(ReplicationSchedule.builder()
            .type(ReplicationScheduleType.EVERY)
            .intervalSeconds(600L)
            .startTime(timePoint("2026-10-21 10:00:00"))
            .endTime(timePoint("2026-10-22 10:00:00"))
            .build())
        .build());

    assertRules(result,
        "hms: every 600s from \"2026-10-21 10:00:00\" to \"2026-10-22 10:00:00\" "
            + "| name matches \"db1.*\" "
            + "| hms-sync -dest thrift://backup:9083 -cascade "
            + "-nameservice_rename \"ns1 ns2\" -include CREATE,DROP");
  }

  @Test
  public void testAllEventsAreNotRestricted() throws Exception {
    for (Set<HiveOperation> events : List.of(
        Set.<HiveOperation>of(), EnumSet.copyOf(HiveOperation.FILTERABLE_OPERATIONS))) {
      RuleGenerationResult result = generator.generate(request(databases("db1"))
          .settings(settings().events(events).build())
          .build());

      assertRules(result, "hms: name matches \"db1.*\" "
          + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"");
    }
  }

  @Test
  public void testSameNameserviceIsNotRenamed() throws Exception {
    assertRules(generator.generate(request(databases("db1"))
            .targetCluster(targetCluster().hdfsNameservice(SOURCE_NAMESERVICE).build())
            .build()),
        "hms: name matches \"db1.*\" | hms-sync -dest thrift://backup:9083");
  }

  @Test
  public void testAtSchedule() throws Exception {
    RuleGenerationResult result = generator.generate(request(databases("db1"))
        .schedule(ReplicationSchedule.builder().type(ReplicationScheduleType.AT).build())
        .build());

    assertRules(result, "hms: at now | name matches \"db1.*\" "
        + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"");
  }

  @Test
  public void testReplicateTablesMatchingPattern() throws Exception {
    ReplicationSource source = databases("db1", "db2").toBuilder()
        .tableNameRegex("sales_*")
        .build();

    RuleGenerationResult result = generator.generate(request(source).build());

    assertRules(result,
        "hms: name matches \"db1.sales_*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"",
        "hms: name matches \"db2.sales_*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"");
  }

  @Test
  public void testMissingTargetClusterSettings() {
    ClusterInfo clusterWithoutThrift = targetCluster().hiveThriftUri(null).build();
    assertThrows(IllegalArgumentException.class,
        () -> generator.generate(request(databases("db1"))
            .targetCluster(clusterWithoutThrift)
            .build()));

    ClusterInfo clusterWithoutNameservice = targetCluster().hdfsNameservice(null).build();
    assertThrows(IllegalArgumentException.class,
        () -> generator.generate(request(databases("db1"))
            .targetCluster(clusterWithoutNameservice)
            .build()));

    assertThrows(IllegalArgumentException.class,
        () -> generator.generate(request(databases("db1"))
            .sourceNameservice(null)
            .build()));
  }

  private static MetadataRuleGenerationRequest.Builder request(ReplicationSource source) {
    return MetadataRuleGenerationRequest.builder()
        .source(source)
        .settings(settings().build())
        .schedule(ReplicationSchedule.eventDriven())
        .targetCluster(targetCluster().build())
        .sourceNameservice(SOURCE_NAMESERVICE);
  }

  private static MetadataReplicationSettings.Builder settings() {
    return MetadataReplicationSettings.builder().enabled(true);
  }

  private static List<String> sources(RuleGenerationResult result) {
    return result.getRules().stream()
        .map(GeneratedRule::getSource)
        .collect(java.util.stream.Collectors.toList());
  }
}
