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
package org.smartdata.server.engine;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.StateTransitionException;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.dao.ClusterDao;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class TestClusterManager extends TestDaoBase {
  private static final Instant CREATE_TIME = Instant.ofEpochMilli(1000L);
  private static final Instant UPDATE_TIME = Instant.ofEpochMilli(2000L);

  private ClusterDao clusterDao;
  private ClusterManager clusterManager;

  @Before
  public void initManager() {
    clusterDao = daoProvider.clusterDao();
    clusterManager = managerAt(CREATE_TIME);
  }

  @Test
  public void testCreateCluster() throws Exception {
    ClusterInfo cluster = clusterManager.createCluster(ClusterInfo.builder()
        .name(" backup ")
        .hdfsUri(" hdfs://backup ")
        .hiveThriftUri(" thrift://backup:9083 ")
        .hdfsNameservice(" backup ")
        // should be ignored
        .id(100L)
        .status(ClusterStatus.COMPLETED)
        .createTime(UPDATE_TIME)
        .build());

    ClusterInfo expectedCluster = ClusterInfo.builder()
        .id(cluster.getId())
        .name("backup")
        .status(ClusterStatus.ACTIVE)
        .hdfsUri("hdfs://backup")
        .hiveThriftUri("thrift://backup:9083")
        .hdfsNameservice("backup")
        .createTime(CREATE_TIME)
        .updateTime(CREATE_TIME)
        .build();
    assertEquals(expectedCluster, cluster);
    assertEquals(expectedCluster, clusterManager.getCluster(cluster.getId()));
  }

  @Test
  public void testCreateClusterWithoutOptionalFields() throws Exception {
    ClusterInfo cluster = clusterManager.createCluster(ClusterInfo.builder()
        .name("backup")
        .hdfsUri("hdfs://backup")
        .hiveThriftUri(" ")
        .build());

    assertEquals(cluster.toBuilder().hiveThriftUri(null).build(), cluster);
    assertEquals(cluster, clusterManager.getCluster(cluster.getId()));
  }

  @Test
  public void testCreateInvalidCluster() {
    assertInvalid(cluster(" ").build());
    assertInvalid(cluster("backup").hdfsUri(null).build());
    assertInvalid(cluster("backup").hdfsUri("/backup").build());
    assertInvalid(cluster("backup").hdfsUri("hdfs:///backup").build());
    assertInvalid(cluster("backup").hdfsUri("hdfs://backup:port with spaces").build());
    // nameservice is required for the metadata replication
    assertInvalid(cluster("backup").hdfsNameservice(null).build());
  }

  @Test
  public void testCreateClusterWithDuplicateName() throws Exception {
    clusterManager.createCluster(cluster("backup").build());

    assertInvalid(cluster("backup").build());
  }

  @Test
  public void testGetUnknownCluster() {
    assertThrows(NotFoundException.class, () -> clusterManager.getCluster(1L));
  }

  @Test
  public void testUpdateCluster() throws Exception {
    ClusterInfo cluster = clusterManager.createCluster(cluster("backup").build());

    ClusterInfo updatedCluster = managerAt(UPDATE_TIME).updateCluster(cluster.getId(),
        ClusterInfo.builder()
            .name("backup_v2")
            .hdfsUri("hdfs://backup_v2")
            .build());

    ClusterInfo expectedCluster = cluster.toBuilder()
        .name("backup_v2")
        .hdfsUri("hdfs://backup_v2")
        .hiveThriftUri(null)
        .hdfsNameservice(null)
        .updateTime(UPDATE_TIME)
        .build();
    assertEquals(expectedCluster, updatedCluster);
    assertEquals(Optional.of(expectedCluster), clusterDao.getById(cluster.getId()));
  }

  @Test
  public void testUpdateInvalidCluster() throws Exception {
    ClusterInfo cluster = clusterManager.createCluster(cluster("backup").build());
    clusterManager.createCluster(cluster("archive").build());

    assertThrows(IllegalArgumentException.class, () -> clusterManager.updateCluster(
        cluster.getId(), cluster("backup").hdfsUri(" ").build()));
    assertThrows(IllegalArgumentException.class, () -> clusterManager.updateCluster(
        cluster.getId(), cluster("archive").build()));

    assertEquals(cluster, clusterManager.getCluster(cluster.getId()));
  }

  @Test
  public void testUpdateUnknownCluster() {
    assertThrows(NotFoundException.class,
        () -> clusterManager.updateCluster(1L, cluster("backup").build()));
  }

  @Test
  public void testCompleteCluster() throws Exception {
    ClusterInfo cluster = clusterManager.createCluster(cluster("backup").build());

    managerAt(UPDATE_TIME).completeCluster(cluster.getId());

    ClusterInfo completedCluster = cluster.toBuilder()
        .status(ClusterStatus.COMPLETED)
        .updateTime(UPDATE_TIME)
        .build();
    assertEquals(completedCluster, clusterManager.getCluster(cluster.getId()));

    // completed cluster can't be modified anymore
    assertThrows(StateTransitionException.class,
        () -> clusterManager.completeCluster(cluster.getId()));
    assertThrows(StateTransitionException.class,
        () -> clusterManager.updateCluster(cluster.getId(), cluster("backup_v2").build()));
    assertEquals(completedCluster, clusterManager.getCluster(cluster.getId()));
  }

  @Test
  public void testCompleteUnknownCluster() {
    assertThrows(NotFoundException.class, () -> clusterManager.completeCluster(1L));
  }

  private void assertInvalid(ClusterInfo cluster) {
    assertThrows(IllegalArgumentException.class, () -> clusterManager.createCluster(cluster));
  }

  private ClusterManager managerAt(Instant now) {
    return new ClusterManager(clusterDao, Clock.fixed(now, ZoneOffset.UTC));
  }

  private static ClusterInfo.Builder cluster(String name) {
    return ClusterInfo.builder()
        .name(name)
        .hdfsUri("hdfs://" + name)
        .hiveThriftUri("thrift://" + name + ":9083")
        .hdfsNameservice(name);
  }
}
