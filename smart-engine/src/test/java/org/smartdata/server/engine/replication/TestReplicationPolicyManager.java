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
package org.smartdata.server.engine.replication;

import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.StateTransitionException;
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.dao.ClusterDao;
import org.smartdata.metastore.dao.ReplicationPolicyDao;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationPolicyStatus;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationScheduleType;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.ClusterManager;
import org.smartdata.server.engine.HiveCatalogManager;
import org.smartdata.server.engine.audit.AuditService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.function.UnaryOperator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.smartdata.metastore.dao.ReplicationTestData.CREATE_TIME;
import static org.smartdata.metastore.dao.ReplicationTestData.cluster;
import static org.smartdata.metastore.dao.ReplicationTestData.policy;
import static org.smartdata.model.replication.ReplicationPolicyStatus.ACTIVE;
import static org.smartdata.model.replication.ReplicationPolicyStatus.COMPLETED;
import static org.smartdata.model.replication.ReplicationPolicyStatus.CREATED;
import static org.smartdata.model.replication.ReplicationPolicyStatus.PAUSED;

public class TestReplicationPolicyManager extends TestDaoBase {
  private static final Instant UPDATE_TIME = Instant.ofEpochMilli(2000L);

  private ReplicationPolicyDao policyDao;
  private ClusterDao clusterDao;
  private AuditService auditService;
  private SmartPrincipalManager principalManager;
  private ClusterManager clusterManager;
  private ReplicationPolicyManager policyManager;
  private long clusterId;

  @Before
  public void init() {
    policyDao = daoProvider.replicationPolicyDao();
    clusterDao = daoProvider.clusterDao();
    auditService = new AuditService(daoProvider.userActivityDao());
    principalManager = new ThreadScopeSmartPrincipalManager(
        new AnonymousDefaultPrincipalProvider());
    clusterManager = new ClusterManager(clusterDao, auditService, principalManager,
        Clock.fixed(CREATE_TIME, ZoneOffset.UTC));
    policyManager = managerAt(CREATE_TIME);
    clusterManager.addListener(policyManager);
    clusterId = clusterDao.insert(cluster("backup").build());

    for (String dbName : Arrays.asList("db1", "db2")) {
      daoProvider.hiveDatabaseDao().upsert(HiveDatabaseInfo.builder()
          .name(dbName)
          .location("hdfs://ns1/warehouse/" + dbName)
          .build());
      for (String tableName : Arrays.asList("sales", "clients")) {
        daoProvider.hiveTableDao().upsert(HiveTableInfo.builder()
            .dbName(dbName)
            .name(tableName)
            .location("hdfs://ns1/warehouse/" + dbName + "/" + tableName)
            .build());
      }
    }
  }

  @Test
  public void testCreatePolicy() throws Exception {
    ReplicationPolicyInfo policy = policyManager.createPolicy(ReplicationPolicyInfo.builder()
        .name(" sales ")
        .description(" ")
        .tags(Arrays.asList(" prod", "finance", "prod "))
        .source(ReplicationSource.builder()
            .databases(Arrays.asList("db2", " db1 ", "db2"))
            .tables(Arrays.asList(
                SourceTable.of("db2", "sales"), SourceTable.of(" db1", "sales ")))
            .build())
        .targetClusterId(clusterId)
        .dataReplication(DataReplicationSettings.builder()
            .enabled(true)
            .preservedAttributes(Collections.emptySet())
            .events(EnumSet.of(FileDiffType.CREATE))
            .build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(false)
            .events(Collections.emptySet())
            .cascade(true)
            .build())
        .schedule(ReplicationSchedule.builder()
            .type(ReplicationScheduleType.AT)
            .startTime(UPDATE_TIME)
            .build())
        // should be ignored
        .id(100L)
        .status(COMPLETED)
        .createTime(UPDATE_TIME)
        .build());

    ReplicationPolicyInfo expectedPolicy = policy("sales", clusterId, "db1")
        .id(policy.getId())
        .tags(Arrays.asList("finance", "prod"))
        .source(ReplicationSource.builder()
            .databases(Arrays.asList("db1", "db2"))
            .tables(Arrays.asList(SourceTable.of("db1", "sales"), SourceTable.of("db2", "sales")))
            .build())
        .dataReplication(DataReplicationSettings.builder()
            .enabled(true)
            .preservedAttributes(Collections.emptySet())
            .events(EnumSet.of(FileDiffType.CREATE))
            .build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(false)
            .events(Collections.emptySet())
            .cascade(true)
            .build())
        .schedule(ReplicationSchedule.builder()
            .type(ReplicationScheduleType.AT)
            .startTime(UPDATE_TIME)
            .build())
        .build();
    assertEquals(expectedPolicy, policy);
    assertEquals(expectedPolicy, policyManager.getPolicy(policy.getId()));
  }

  @Test
  public void testCreatePolicyWithOmittedSettings() throws Exception {
    // omitted optional settings are kept, their defaults are applied on the rules generation
    ReplicationPolicyInfo policy = policyManager.createPolicy(ReplicationPolicyInfo.builder()
        .name("sales")
        .source(ReplicationSource.builder()
            .databases(Collections.singletonList("db1"))
            .tableNameRegex(" sales_.* ")
            .build())
        .targetClusterId(clusterId)
        .dataReplication(DataReplicationSettings.builder().enabled(true).build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(true)
            .events(Collections.emptySet())
            .build())
        .schedule(ReplicationSchedule.eventDriven())
        .build());

    ReplicationPolicyInfo expectedPolicy = ReplicationPolicyInfo.builder()
        .id(policy.getId())
        .name("sales")
        .status(CREATED)
        .source(ReplicationSource.builder()
            .databases(Collections.singletonList("db1"))
            .tableNameRegex("sales_.*")
            .build())
        .targetClusterId(clusterId)
        .dataReplication(DataReplicationSettings.builder().enabled(true).build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(true)
            .events(Collections.emptySet())
            .build())
        .schedule(ReplicationSchedule.eventDriven())
        .createTime(CREATE_TIME)
        .updateTime(CREATE_TIME)
        .build();
    assertEquals(expectedPolicy, policy);
    assertEquals(expectedPolicy, policyManager.getPolicy(policy.getId()));
  }

  @Test
  public void testCreateInvalidPolicy() throws Exception {
    assertInvalid(policy -> policy.name(" "));
    assertInvalid(policy -> policy.tags(Collections.singletonList(" ")));

    // source
    assertInvalid(policy -> policy.source(null));
    assertInvalid(policy -> policy.source(source().databases(Collections.emptyList()).build()));
    assertInvalid(policy -> policy.source(source().databases(Collections.singletonList("unknown")).build()));
    assertInvalid(policy -> policy.source(source()
        .tables(Collections.singletonList(SourceTable.of("db2", "sales")))
        .build()));
    assertInvalid(policy -> policy.source(source()
        .tables(Collections.singletonList(SourceTable.of("db1", "unknown")))
        .build()));
    assertInvalid(policy -> policy.source(source().tableNameRegex("sales_[").build()));
    assertInvalid(policy -> policy.source(source()
        .tables(Collections.singletonList(SourceTable.of("db1", "sales")))
        .tableNameRegex("sales_.*")
        .build()));

    // target cluster
    assertInvalid(policy -> policy.targetClusterId(null));
    assertInvalid(policy -> policy.targetClusterId(clusterId + 100));
    long completedClusterId = clusterDao.insert(cluster("completed")
        .status(ClusterStatus.COMPLETED)
        .build());
    assertInvalid(policy -> policy.targetClusterId(completedClusterId));
    long hdfsOnlyClusterId = clusterDao.insert(cluster("hdfs_only")
        .hiveThriftUri(null)
        .hdfsNameservice(null)
        .build());
    assertInvalid(policy -> policy.targetClusterId(hdfsOnlyClusterId));

    // replication settings
    assertInvalid(policy -> policy.dataReplication(null));
    assertInvalid(policy -> policy.metadataReplication(null));
    assertInvalid(policy -> policy
        .dataReplication(DataReplicationSettings.builder().enabled(false).build())
        .metadataReplication(MetadataReplicationSettings.builder().enabled(false).build()));
    assertInvalid(policy -> policy.dataReplication(DataReplicationSettings.builder()
        .enabled(true)
        .events(EnumSet.of(FileDiffType.BASESYNC))
        .build()));
    assertInvalid(policy -> policy.metadataReplication(MetadataReplicationSettings.builder()
        .enabled(true)
        .events(EnumSet.of(HiveOperation.UNKNOWN))
        .build()));

    // schedule
    assertInvalid(policy -> policy.schedule(null));
    assertInvalid(policy -> policy.schedule(ReplicationSchedule.builder().build()));
    assertInvalid(policy -> policy.schedule(ReplicationSchedule.builder()
        .type(ReplicationScheduleType.EVENT_DRIVEN)
        .intervalSeconds(10L)
        .build()));
    assertInvalid(policy -> policy.schedule(ReplicationSchedule.builder()
        .type(ReplicationScheduleType.AT)
        .endTime(UPDATE_TIME)
        .build()));
    assertInvalid(policy -> policy.schedule(ReplicationSchedule.builder()
        .type(ReplicationScheduleType.EVERY)
        .build()));
    assertInvalid(policy -> policy.schedule(ReplicationSchedule.builder()
        .type(ReplicationScheduleType.EVERY)
        .intervalSeconds(10L)
        .startTime(UPDATE_TIME)
        .endTime(CREATE_TIME)
        .build()));

    assertEquals(0L, policyManager.getPoliciesInfo().getTotalPolicies());
  }

  @Test
  public void testCreatePolicyWithDuplicateName() throws Exception {
    policyManager.createPolicy(policy("sales", clusterId, "db1").build());

    assertThrows(IllegalArgumentException.class,
        () -> policyManager.createPolicy(policy("sales", clusterId, "db2").build()));
  }

  @Test
  public void testGetUnknownPolicy() {
    assertThrows(NotFoundException.class, () -> policyManager.getPolicy(1L));
  }

  @Test
  public void testUpdatePolicy() throws Exception {
    ReplicationPolicyInfo policy = policyManager.createPolicy(
        policy("sales", clusterId, "db1").build());
    policyManager.startPolicy(policy.getId());

    ReplicationPolicyInfo updatedPolicy = managerAt(UPDATE_TIME).updatePolicy(policy.getId(),
        policy("sales_v2", clusterId, "db2")
            .tags(Collections.singletonList("prod"))
            .status(COMPLETED)
            .build());

    ReplicationPolicyInfo expectedPolicy = policy("sales_v2", clusterId, "db2")
        .id(policy.getId())
        .status(ACTIVE)
        .tags(Collections.singletonList("prod"))
        .updateTime(UPDATE_TIME)
        .build();
    assertEquals(expectedPolicy, updatedPolicy);
    assertEquals(expectedPolicy, policyManager.getPolicy(policy.getId()));
  }

  @Test
  public void testUpdateUnknownPolicy() {
    assertThrows(NotFoundException.class, () -> policyManager.updatePolicy(
        1L, policy("sales", clusterId, "db1").build()));
  }

  @Test
  public void testStatusTransitions() throws Exception {
    long id = policyManager.createPolicy(policy("sales", clusterId, "db1").build()).getId();

    assertStatusTransitionFails(() -> policyManager.pausePolicy(id));

    managerAt(UPDATE_TIME).startPolicy(id);
    assertStatus(id, ACTIVE);
    assertEquals(UPDATE_TIME, policyManager.getPolicy(id).getUpdateTime());
    assertStatusTransitionFails(() -> policyManager.startPolicy(id));

    policyManager.pausePolicy(id);
    assertStatus(id, PAUSED);
    assertStatusTransitionFails(() -> policyManager.pausePolicy(id));

    policyManager.startPolicy(id);
    assertStatus(id, ACTIVE);

    policyManager.completePolicy(id);
    assertStatus(id, COMPLETED);

    // completed policy can't be launched or modified anymore
    assertStatusTransitionFails(() -> policyManager.startPolicy(id));
    assertStatusTransitionFails(() -> policyManager.pausePolicy(id));
    assertStatusTransitionFails(() -> policyManager.completePolicy(id));
    assertStatusTransitionFails(() -> policyManager.updatePolicy(
        id, policy("sales_v2", clusterId, "db1").build()));
    assertEquals("sales", policyManager.getPolicy(id).getName());

    assertThrows(NotFoundException.class, () -> policyManager.startPolicy(id + 1));
  }

  @Test
  public void testCompleteCreatedPolicy() throws Exception {
    long id = policyManager.createPolicy(policy("sales", clusterId, "db1").build()).getId();

    policyManager.completePolicy(id);

    assertStatus(id, COMPLETED);
  }

  @Test
  public void testGetPoliciesInfoAndTags() throws Exception {
    long salesId = policyManager.createPolicy(policy("sales", clusterId, "db1")
        .tags(Arrays.asList("prod", "finance"))
        .build()).getId();
    policyManager.createPolicy(policy("clients", clusterId, "db1")
        .tags(Collections.singletonList("crm"))
        .build());
    policyManager.startPolicy(salesId);

    assertEquals(2L, policyManager.getPoliciesInfo().getTotalPolicies());
    assertEquals(1L, policyManager.getPoliciesInfo().getActivePolicies());
    assertEquals(Arrays.asList("crm", "finance", "prod"), policyManager.getTags());
  }

  @Test
  public void testCompleteClusterWithNotCompletedPolicies() throws Exception {
    long policyId = policyManager.createPolicy(policy("sales", clusterId, "db1").build()).getId();
    long anotherPolicyId = policyManager.createPolicy(policy("clients", clusterId, "db1").build())
        .getId();
    policyManager.completePolicy(anotherPolicyId);

    assertThrows(StateTransitionException.class, () -> clusterManager.completeCluster(clusterId));
    assertEquals(ClusterStatus.ACTIVE, clusterManager.getCluster(clusterId).getStatus());

    policyManager.completePolicy(policyId);
    clusterManager.completeCluster(clusterId);

    assertEquals(ClusterStatus.COMPLETED, clusterManager.getCluster(clusterId).getStatus());
  }

  @Test
  public void testRemoveThriftUriUsedForMetadataReplication() throws Exception {
    ReplicationPolicyInfo policy = policyManager.createPolicy(
        policy("sales", clusterId, "db1").build());
    ClusterInfo clusterWithoutThriftUri = cluster("backup")
        .hiveThriftUri(null)
        .hdfsNameservice(null)
        .build();

    assertThrows(IllegalArgumentException.class,
        () -> clusterManager.updateCluster(clusterId, clusterWithoutThriftUri));
    assertEquals("thrift://backup:9083", clusterManager.getCluster(clusterId).getHiveThriftUri());

    // policies without metadata replication don't use Thrift URI
    policyManager.updatePolicy(policy.getId(), policy.toBuilder()
        .metadataReplication(MetadataReplicationSettings.builder().enabled(false).build())
        .build());
    clusterManager.updateCluster(clusterId, clusterWithoutThriftUri);

    assertNull(clusterManager.getCluster(clusterId).getHiveThriftUri());
  }

  private void assertInvalid(UnaryOperator<ReplicationPolicyInfo.Builder> policyModifier) {
    ReplicationPolicyInfo policy = policyModifier.apply(
        policy("sales", clusterId, "db1")).build();
    assertThrows(IllegalArgumentException.class, () -> policyManager.createPolicy(policy));
  }

  private void assertStatusTransitionFails(ThrowingRunnable action) {
    assertThrows(StateTransitionException.class, action);
  }

  private void assertStatus(long id, ReplicationPolicyStatus expectedStatus) throws Exception {
    assertEquals(expectedStatus, policyManager.getPolicy(id).getStatus());
  }

  private ReplicationPolicyManager managerAt(Instant now) {
    return new ReplicationPolicyManager(policyDao, clusterManager,
        new HiveCatalogManager(daoProvider.hiveDatabaseDao(), daoProvider.hiveTableDao()),
        auditService, principalManager, Clock.fixed(now, ZoneOffset.UTC));
  }

  private static ReplicationSource.Builder source() {
    return ReplicationSource.builder()
        .databases(Collections.singletonList("db1"));
  }
}
