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
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.ClusterInfo;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.ClusterManager;

import java.time.Clock;

import static org.junit.Assert.assertThrows;
import static org.smartdata.model.audit.UserActivityObject.CLUSTER;

public class TestClusterLifecycleLogger extends TestDaoBase {
  private AuditEventsTestSupport auditSupport;
  private ClusterManager clusterManager;

  @Before
  public void init() {
    AuditService auditService = new AuditService(daoProvider.userActivityDao());
    auditSupport = new AuditEventsTestSupport(auditService);
    clusterManager = new ClusterManager(daoProvider.clusterDao(), auditService,
        new ThreadScopeSmartPrincipalManager(new AnonymousDefaultPrincipalProvider()),
        Clock.systemUTC());
  }

  @Test
  public void testCreateCluster() throws Exception {
    long id = clusterManager.createCluster(cluster("backup")).getId();

    auditSupport.assertEvents(CLUSTER, id + " CREATE SUCCESS");
  }

  @Test
  public void testCreateInvalidCluster() throws Exception {
    assertThrows(IllegalArgumentException.class,
        () -> clusterManager.createCluster(cluster(" ")));

    // id of the failed creation is unknown
    auditSupport.assertEvents(CLUSTER, "null CREATE FAILURE");
  }

  @Test
  public void testCompleteCluster() throws Exception {
    long id = clusterManager.createCluster(cluster("backup")).getId();

    clusterManager.completeCluster(id);
    assertThrows(Exception.class, () -> clusterManager.completeCluster(id));

    auditSupport.assertEvents(CLUSTER,
        id + " CREATE SUCCESS",
        id + " DELETE SUCCESS",
        id + " DELETE FAILURE");
  }

  @Test
  public void testUpdateClusterIsNotAudited() throws Exception {
    long id = clusterManager.createCluster(cluster("backup")).getId();

    clusterManager.updateCluster(id, cluster("backup_v2"));

    auditSupport.assertEvents(CLUSTER, id + " CREATE SUCCESS");
  }

  private static ClusterInfo cluster(String name) {
    return ClusterInfo.builder()
        .name(name)
        .hdfsUri("hdfs://backup")
        .build();
  }
}
