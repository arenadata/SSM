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
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationSchedule;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.smartdata.server.engine.replication.rule.RuleAssertions.assertRules;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.SOURCE_NAMESERVICE;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.databases;
import static org.smartdata.server.engine.replication.rule.RuleGenerationTestData.targetCluster;

public class TestReplicationRuleGenerator {

  @Test
  public void testGenerateMetadataAndDataRules() throws Exception {
    ReplicationRuleGenerator generator = new ReplicationRuleGenerator();

    RuleGenerationResult result = generator.generate(request(true, true));

    assertRules(result,
        "hms: name matches \"db1.*\" "
            + "| hms-sync -dest thrift://backup:9083 -nameservice_rename \"ns1 ns2\"",
        "file: path matches \"/external/sales/*\" "
            + "| sync -dest hdfs://ns2/external/sales/ -preserve owner,group,permissions",
        "file: path matches \"/warehouse/db1.db/*\" "
            + "| sync -dest hdfs://ns2/warehouse/db1.db/ -preserve owner,group,permissions");
  }

  @Test
  public void testDelegateToGenerators() throws Exception {
    List<MetadataRuleGenerationRequest> metadataRequests = new ArrayList<>();
    List<DataRuleGenerationRequest> dataRequests = new ArrayList<>();
    ReplicationRuleGenerator generator = new ReplicationRuleGenerator(
        request -> {
          metadataRequests.add(request);
          return RuleGenerationResult.empty();
        },
        request -> {
          dataRequests.add(request);
          return RuleGenerationResult.empty();
        });

    ReplicationRuleGenerationRequest request = request(true, false);
    assertEquals(RuleGenerationResult.empty(), generator.generate(request));

    MetadataRuleGenerationRequest metadataRequest = metadataRequests.get(0);
    assertSame(request.getSource(), metadataRequest.getSource());
    assertSame(request.getMetadataReplication(), metadataRequest.getSettings());
    assertSame(request.getSchedule(), metadataRequest.getSchedule());
    assertSame(request.getTargetCluster(), metadataRequest.getTargetCluster());
    assertEquals(SOURCE_NAMESERVICE, metadataRequest.getSourceNameservice());

    DataRuleGenerationRequest dataRequest = dataRequests.get(0);
    assertSame(request.getDataRoots(), dataRequest.getRoots());
    assertSame(request.getDataReplication(), dataRequest.getSettings());
    assertSame(request.getSchedule(), dataRequest.getSchedule());
    assertSame(request.getTargetCluster(), dataRequest.getTargetCluster());
  }

  private static ReplicationRuleGenerationRequest request(
      boolean metadataEnabled, boolean dataEnabled) {
    ClusterInfo targetCluster = targetCluster().build();
    return ReplicationRuleGenerationRequest.builder()
        .source(databases("db1"))
        .dataRoots(List.of("/warehouse/db1.db/", "/external/sales/"))
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(metadataEnabled)
            .build())
        .dataReplication(DataReplicationSettings.builder()
            .enabled(dataEnabled)
            .build())
        .schedule(ReplicationSchedule.eventDriven())
        .targetCluster(targetCluster)
        .sourceNameservice(SOURCE_NAMESERVICE)
        .build();
  }
}
