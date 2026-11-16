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

import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.ClusterManager;
import org.smartdata.server.engine.HiveCatalogManager;
import org.smartdata.server.engine.replication.ReplicationPolicyManager;

import java.time.Clock;

import static org.junit.Assert.assertThrows;
import static org.smartdata.metastore.dao.ReplicationTestData.cluster;
import static org.smartdata.metastore.dao.ReplicationTestData.policy;
import static org.smartdata.model.audit.UserActivityObject.REPLICATION_POLICY;

public class TestReplicationPolicyLifecycleLogger extends TestDaoBase {
  private AuditEventsTestSupport auditSupport;
  private ReplicationPolicyManager policyManager;
  private long clusterId;

  @Before
  public void init() {
    AuditService auditService = new AuditService(daoProvider.userActivityDao());
    SmartPrincipalManager principalManager =
        new ThreadScopeSmartPrincipalManager(new AnonymousDefaultPrincipalProvider());
    auditSupport = new AuditEventsTestSupport(auditService);

    ClusterManager clusterManager = new ClusterManager(
        daoProvider.clusterDao(), auditService, principalManager, Clock.systemUTC());
    policyManager = new ReplicationPolicyManager(daoProvider.replicationPolicyDao(),
        clusterManager,
        new HiveCatalogManager(daoProvider.hiveDatabaseDao(), daoProvider.hiveTableDao()),
        auditService, principalManager, Clock.systemUTC());

    clusterId = daoProvider.clusterDao().insert(cluster("backup").build());
    daoProvider.hiveDatabaseDao().upsert(HiveDatabaseInfo.builder()
        .name("db1")
        .location("hdfs://ns1/warehouse/db1")
        .build());
  }

  @Test
  public void testCreatePolicy() throws Exception {
    long id = policyManager.createPolicy(policy("sales", clusterId, "db1").build()).getId();

    auditSupport.assertEvents(REPLICATION_POLICY, id + " CREATE SUCCESS");
  }

  @Test
  public void testCreateInvalidPolicy() throws Exception {
    assertThrows(IllegalArgumentException.class,
        () -> policyManager.createPolicy(policy("sales", clusterId, "unknown").build()));

    // id of the failed creation is unknown
    auditSupport.assertEvents(REPLICATION_POLICY, "null CREATE FAILURE");
  }

  @Test
  public void testStatusTransitions() throws Exception {
    long id = policyManager.createPolicy(policy("sales", clusterId, "db1").build()).getId();

    policyManager.startPolicy(id);
    policyManager.pausePolicy(id);
    policyManager.completePolicy(id);
    assertThrows(Exception.class, () -> policyManager.startPolicy(id));

    auditSupport.assertEvents(REPLICATION_POLICY,
        id + " CREATE SUCCESS",
        id + " START SUCCESS",
        id + " STOP SUCCESS",
        id + " DELETE SUCCESS",
        id + " START FAILURE");
  }

  @Test
  public void testUpdatePolicyIsNotAudited() throws Exception {
    ReplicationPolicyInfo policy = policyManager.createPolicy(
        policy("sales", clusterId, "db1").build());

    policyManager.updatePolicy(policy.getId(), policy.toBuilder().name("sales_v2").build());

    auditSupport.assertEvents(REPLICATION_POLICY, policy.getId() + " CREATE SUCCESS");
  }
}
