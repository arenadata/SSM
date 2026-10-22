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
package org.smartdata.metastore.dao;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.queries.sort.ReplicationPolicySortField;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.PreserveAttribute;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationPoliciesInfo;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationPolicyStatus;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationScheduleType;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.model.request.ReplicationPolicySearchRequest;
import org.springframework.dao.DuplicateKeyException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.ReplicationTestData.cluster;
import static org.smartdata.metastore.dao.ReplicationTestData.policy;

public class TestReplicationPolicyDao extends TestDaoBase {
  private ReplicationPolicyDao policyDao;
  private long clusterId;

  @Before
  public void initDao() {
    policyDao = daoProvider.replicationPolicyDao();
    clusterId = daoProvider.clusterDao().insert(cluster("backup").build());
  }

  @Test
  public void testInsertAndGetById() {
    ReplicationPolicyInfo policy = fullPolicy("sales").build();
    long id = policyDao.insert(policy);

    assertEquals(Optional.of(policy.toBuilder().id(id).build()), policyDao.getById(id));
    assertEquals(Optional.empty(), policyDao.getById(id + 1));
  }

  @Test
  public void testInsertWithDefaultSettings() {
    ReplicationPolicyInfo policy = policy("sales", clusterId, "db1").build();
    long id = policyDao.insert(policy);

    assertEquals(Optional.of(policy.toBuilder().id(id).build()), policyDao.getById(id));
  }

  @Test
  public void testInsertAndUpdateWithOmittedSettings() {
    ReplicationPolicyInfo policy = policy("sales", clusterId, "db1")
        .tags(null)
        .source(ReplicationSource.builder()
            .databases(Collections.singletonList("db1"))
            .build())
        .dataReplication(DataReplicationSettings.builder().enabled(true).build())
        .metadataReplication(MetadataReplicationSettings.builder().enabled(false).build())
        .build();
    long id = policyDao.insert(policy);

    // omitted settings should be distinguishable from the empty ones
    assertEquals(Optional.of(policy.toBuilder().id(id).build()), policyDao.getById(id));

    ReplicationPolicyInfo updatedPolicy = fullPolicy("sales").id(id).build();
    policyDao.update(updatedPolicy);
    assertEquals(Optional.of(updatedPolicy), policyDao.getById(id));

    // settings should be unset on the update
    policyDao.update(policy.toBuilder().id(id).build());
    assertEquals(Optional.of(policy.toBuilder().id(id).build()), policyDao.getById(id));
  }

  @Test
  public void testInsertWithDuplicateName() {
    policyDao.insert(policy("sales", clusterId, "db1").build());

    assertThrows(DuplicateKeyException.class,
        () -> policyDao.insert(policy("sales", clusterId, "db2").build()));
  }

  @Test
  public void testUpdate() {
    long id = policyDao.insert(fullPolicy("sales").build());
    long anotherId = policyDao.insert(fullPolicy("clients").build());

    // child entities should be replaced and optional fields unset
    ReplicationPolicyInfo updatedPolicy = policy("sales_v2", clusterId, "db3")
        .id(id)
        .status(ReplicationPolicyStatus.PAUSED)
        .tags(Collections.singletonList("new"))
        .updateTime(Instant.ofEpochMilli(2000L))
        .build();
    assertTrue(policyDao.update(updatedPolicy));

    assertEquals(Optional.of(updatedPolicy), policyDao.getById(id));
    assertEquals(Optional.of(fullPolicy("clients").id(anotherId).build()),
        policyDao.getById(anotherId));
  }

  @Test
  public void testUpdateCreateTimeIsIgnored() {
    long id = policyDao.insert(policy("sales", clusterId, "db1").build());

    ReplicationPolicyInfo updatedPolicy = policy("sales", clusterId, "db1")
        .id(id)
        .createTime(Instant.ofEpochMilli(5000L))
        .build();
    assertTrue(policyDao.update(updatedPolicy));

    assertEquals(Optional.of(updatedPolicy.toBuilder()
            .createTime(ReplicationTestData.CREATE_TIME)
            .build()),
        policyDao.getById(id));
  }

  @Test
  public void testUpdateNonExistentPolicy() {
    assertFalse(policyDao.update(policy("sales", clusterId, "db1").id(1L).build()));
  }

  @Test
  public void testSearch() throws Exception {
    long anotherClusterId = daoProvider.clusterDao().insert(cluster("archive").build());

    long salesId = policyDao.insert(fullPolicy("sales").build());
    long salesArchiveId = policyDao.insert(policy("sales_archive", anotherClusterId, "db1")
        .status(ReplicationPolicyStatus.ACTIVE)
        .build());
    long clientsId = policyDao.insert(policy("clients", clusterId, "db2")
        .status(ReplicationPolicyStatus.COMPLETED)
        .build());

    SearchableTestSupport<ReplicationPolicySearchRequest, ReplicationPolicyInfo,
        ReplicationPolicySortField, Long> searchSupport = new SearchableTestSupport<>(
        policyDao, ReplicationPolicySortField.ID, ReplicationPolicyInfo::getId);

    searchSupport.testSearch(ReplicationPolicySearchRequest.noFilters(),
        salesId, salesArchiveId, clientsId);
    searchSupport.testSearch(ReplicationPolicySearchRequest.builder()
            .nameLike("SALES")
            .build(),
        salesId, salesArchiveId);
    searchSupport.testSearch(ReplicationPolicySearchRequest.builder()
            .statuses(Arrays.asList(
                ReplicationPolicyStatus.CREATED, ReplicationPolicyStatus.COMPLETED))
            .build(),
        salesId, clientsId);
    searchSupport.testSearch(ReplicationPolicySearchRequest.builder()
            .targetClusterIds(Collections.singletonList(clusterId))
            .statuses(Collections.singletonList(ReplicationPolicyStatus.CREATED))
            .build(),
        salesId);
    searchSupport.testSearch(ReplicationPolicySearchRequest.builder()
        .nameLike("unknown")
        .build());

    // found policies should contain child entities
    assertEquals(Collections.singletonList(fullPolicy("sales").id(salesId).build()),
        policyDao.search(ReplicationPolicySearchRequest.builder()
            .nameLike("sales")
            .targetClusterIds(Collections.singletonList(clusterId))
            .build()));
  }

  @Test
  public void testGetTags() {
    assertTrue(policyDao.getTags().isEmpty());

    policyDao.insert(policy("sales", clusterId, "db1")
        .tags(Arrays.asList("prod", "finance"))
        .build());
    policyDao.insert(policy("clients", clusterId, "db1")
        .tags(Arrays.asList("prod", "crm"))
        .build());

    assertEquals(Arrays.asList("crm", "finance", "prod"), policyDao.getTags());
  }

  @Test
  public void testGetPoliciesInfo() {
    assertEquals(new ReplicationPoliciesInfo(0L, 0L), policyDao.getPoliciesInfo());

    policyDao.insert(policy("sales", clusterId, "db1")
        .status(ReplicationPolicyStatus.ACTIVE)
        .build());
    policyDao.insert(policy("clients", clusterId, "db1")
        .status(ReplicationPolicyStatus.PAUSED)
        .build());
    policyDao.insert(policy("orders", clusterId, "db1").build());

    assertEquals(new ReplicationPoliciesInfo(3L, 1L), policyDao.getPoliciesInfo());
  }

  private ReplicationPolicyInfo.Builder fullPolicy(String name) {
    return policy(name, clusterId, "db1")
        .description("Replication of " + name)
        .tags(Arrays.asList("finance", "prod"))
        .source(ReplicationSource.builder()
            .databases(Arrays.asList("db1", "db2"))
            .tables(Arrays.asList(SourceTable.of("db1", name), SourceTable.of("db2", name)))
            .tableNameRegex(name + "_*")
            .build())
        .dataReplication(DataReplicationSettings.builder()
            .enabled(false)
            .preservedAttributes(EnumSet.of(PreserveAttribute.MODIFICATION_TIME))
            .events(EnumSet.of(FileDiffType.CREATE, FileDiffType.APPEND))
            .build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(true)
            .events(EnumSet.noneOf(HiveOperation.class))
            .cascade(true)
            .build())
        .schedule(ReplicationSchedule.builder()
            .type(ReplicationScheduleType.EVERY)
            .intervalSeconds(300L)
            .startTime(Instant.ofEpochMilli(10_000L))
            .endTime(Instant.ofEpochMilli(20_000L))
            .build());
  }
}
