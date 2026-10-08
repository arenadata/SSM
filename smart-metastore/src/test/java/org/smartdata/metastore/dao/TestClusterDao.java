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
import org.smartdata.metastore.queries.sort.ClusterSortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.request.ClusterSearchRequest;
import org.springframework.dao.DuplicateKeyException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestClusterDao extends TestDaoBase {
  private static final Instant CREATE_TIME = Instant.ofEpochMilli(1000L);

  private ClusterDao clusterDao;

  @Before
  public void initDao() {
    clusterDao = daoProvider.clusterDao();
  }

  @Test
  public void testInsertAndGetById() {
    ClusterInfo cluster = cluster("backup").build();
    long id = clusterDao.insert(cluster);

    assertEquals(Optional.of(cluster.toBuilder().id(id).build()), clusterDao.getById(id));
    assertEquals(Optional.empty(), clusterDao.getById(id + 1));
  }

  @Test
  public void testInsertWithoutOptionalFields() {
    ClusterInfo cluster = cluster("backup")
        .hiveThriftUri(null)
        .hdfsNameservice(null)
        .build();
    long id = clusterDao.insert(cluster);

    assertEquals(Optional.of(cluster.toBuilder().id(id).build()), clusterDao.getById(id));
  }

  @Test
  public void testInsertWithDuplicateName() {
    clusterDao.insert(cluster("backup").build());

    assertThrows(DuplicateKeyException.class,
        () -> clusterDao.insert(cluster("backup").build()));
  }

  @Test
  public void testUpdate() {
    long id = clusterDao.insert(cluster("backup").build());
    long anotherId = clusterDao.insert(cluster("archive").build());

    ClusterInfo updatedCluster = cluster("backup_v2")
        .id(id)
        .status(ClusterStatus.COMPLETED)
        .hdfsUri("hdfs://backup_v2")
        // optional fields should be unset
        .hiveThriftUri(null)
        .hdfsNameservice(null)
        .updateTime(Instant.ofEpochMilli(2000L))
        .build();
    assertTrue(clusterDao.update(updatedCluster));

    assertEquals(Optional.of(updatedCluster), clusterDao.getById(id));
    assertEquals("archive", clusterDao.getById(anotherId).map(ClusterInfo::getName).orElse(null));
  }

  @Test
  public void testUpdateCreateTimeIsIgnored() {
    long id = clusterDao.insert(cluster("backup").build());

    ClusterInfo updatedCluster = cluster("backup")
        .id(id)
        .createTime(Instant.ofEpochMilli(5000L))
        .build();
    assertTrue(clusterDao.update(updatedCluster));

    assertEquals(Optional.of(updatedCluster.toBuilder().createTime(CREATE_TIME).build()),
        clusterDao.getById(id));
  }

  @Test
  public void testUpdateNonExistentCluster() {
    assertFalse(clusterDao.update(cluster("backup").id(1L).build()));
  }

  @Test
  public void testUpdateWithDuplicateName() {
    clusterDao.insert(cluster("backup").build());
    long id = clusterDao.insert(cluster("archive").build());

    assertThrows(DuplicateKeyException.class,
        () -> clusterDao.update(cluster("backup").id(id).build()));
  }

  @Test
  public void testSearch() {
    long backupId = clusterDao.insert(cluster("backup").build());
    long backupDrId = clusterDao.insert(cluster("backup_dr")
        .status(ClusterStatus.COMPLETED)
        .build());
    long archiveId = clusterDao.insert(cluster("archive").build());

    SearchableTestSupport<ClusterSearchRequest, ClusterInfo, ClusterSortField, Long>
        searchSupport = new SearchableTestSupport<>(
        clusterDao, ClusterSortField.ID, ClusterInfo::getId);

    searchSupport.testSearch(ClusterSearchRequest.noFilters(),
        backupId, backupDrId, archiveId);
    searchSupport.testSearch(ClusterSearchRequest.builder()
            .nameLike("BACKUP")
            .build(),
        backupId, backupDrId);
    searchSupport.testSearch(ClusterSearchRequest.builder()
            .statuses(Collections.singletonList(ClusterStatus.ACTIVE))
            .build(),
        backupId, archiveId);
    searchSupport.testSearch(ClusterSearchRequest.builder()
            .nameLike("backup")
            .statuses(Arrays.asList(ClusterStatus.ACTIVE, ClusterStatus.COMPLETED))
            .build(),
        backupId, backupDrId);
    searchSupport.testSearch(ClusterSearchRequest.builder()
        .nameLike("unknown")
        .build());
  }

  private static ClusterInfo.Builder cluster(String name) {
    return ClusterInfo.builder()
        .name(name)
        .status(ClusterStatus.ACTIVE)
        .hdfsUri("hdfs://" + name)
        .hiveThriftUri("thrift://" + name + ":9083")
        .hdfsNameservice(name)
        .createTime(CREATE_TIME)
        .updateTime(CREATE_TIME);
  }
}
