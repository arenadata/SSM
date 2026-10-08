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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.StateTransitionException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.dao.ClusterDao;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.ClusterSortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.request.ClusterSearchRequest;
import org.springframework.dao.DuplicateKeyException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

import static org.smartdata.metastore.utils.MetaStoreUtils.logAndBuildMetastoreException;

/**
 * Manages the target clusters of the replication policies.
 */
@Slf4j
public class ClusterManager {
  private final ClusterDao clusterDao;
  private final Searchable<ClusterSearchRequest, ClusterInfo, ClusterSortField> searchService;
  private final Clock clock;

  public ClusterManager(MetaStore metaStore) {
    this(metaStore.clusterDao(), Clock.systemUTC());
  }

  public ClusterManager(ClusterDao clusterDao, Clock clock) {
    this.clusterDao = clusterDao;
    this.searchService = new SearchableService<>(clusterDao, "clusters");
    this.clock = clock;
  }

  public SearchResult<ClusterInfo> search(
      ClusterSearchRequest searchRequest,
      PageRequest<ClusterSortField> pageRequest) throws IOException {
    return searchService.search(searchRequest, pageRequest);
  }

  public ClusterInfo getCluster(long id) throws IOException {
    Optional<ClusterInfo> cluster = executeDbOperation(
        () -> clusterDao.getById(id), "Error fetching cluster " + id);
    return cluster.orElseThrow(
        () -> NotFoundException.forIdentifiableEntity("Cluster", id));
  }

  /**
   * Creates the cluster in the {@link ClusterStatus#ACTIVE} status.
   *
   * @param cluster cluster settings: name, HDFS URI, Hive Thrift URI and HDFS nameservice.
   *                The rest of the fields are ignored.
   */
  public ClusterInfo createCluster(ClusterInfo cluster) throws IOException {
    Instant now = clock.instant();
    ClusterInfo newCluster = withValidatedSettings(
        ClusterInfo.builder()
            .status(ClusterStatus.ACTIVE)
            .createTime(now)
            .updateTime(now)
            .build(),
        cluster);

    long id = executeDbOperation(
        () -> clusterDao.insert(newCluster),
        "Error creating cluster " + newCluster.getName());
    return newCluster.toBuilder()
        .id(id)
        .build();
  }

  /**
   * Updates settings of the cluster, which isn't {@link ClusterStatus#COMPLETED completed}.
   *
   * @param cluster new cluster settings: name, HDFS URI, Hive Thrift URI and HDFS nameservice.
   *                The rest of the fields are ignored.
   */
  public ClusterInfo updateCluster(long id, ClusterInfo cluster) throws IOException {
    ClusterInfo oldCluster = getCluster(id);
    if (oldCluster.getStatus() == ClusterStatus.COMPLETED) {
      throw new StateTransitionException("Completed cluster can't be updated: " + id);
    }

    ClusterInfo updatedCluster = withValidatedSettings(oldCluster, cluster)
        .toBuilder()
        .updateTime(clock.instant())
        .build();
    update(updatedCluster);
    return updatedCluster;
  }

  /**
   * Decommissions the cluster, after which it can't be used or modified anymore.
   */
  public void completeCluster(long id) throws IOException {
    ClusterInfo cluster = getCluster(id);
    if (cluster.getStatus() == ClusterStatus.COMPLETED) {
      throw StateTransitionException.forCluster(cluster.getStatus(), ClusterStatus.COMPLETED);
    }

    update(cluster.toBuilder()
        .status(ClusterStatus.COMPLETED)
        .updateTime(clock.instant())
        .build());
  }

  private void update(ClusterInfo cluster) throws IOException {
    boolean updated = executeDbOperation(
        () -> clusterDao.update(cluster), "Error updating cluster " + cluster.getId());
    if (!updated) {
      throw NotFoundException.forIdentifiableEntity("Cluster", cluster.getId());
    }
  }

  private ClusterInfo withValidatedSettings(ClusterInfo target, ClusterInfo settings) {
    String name = StringUtils.trimToNull(settings.getName());
    String hdfsUri = StringUtils.trimToNull(settings.getHdfsUri());
    String hiveThriftUri = StringUtils.trimToNull(settings.getHiveThriftUri());
    String hdfsNameservice = StringUtils.trimToNull(settings.getHdfsNameservice());

    if (name == null) {
      throw new IllegalArgumentException("Cluster name can't be empty");
    }
    validateHdfsUri(hdfsUri);
    if (hiveThriftUri != null && hdfsNameservice == null) {
      throw new IllegalArgumentException(
          "HDFS nameservice should be set along with the Hive Thrift URI");
    }

    return target.toBuilder()
        .name(name)
        .hdfsUri(hdfsUri)
        .hiveThriftUri(hiveThriftUri)
        .hdfsNameservice(hdfsNameservice)
        .build();
  }

  private void validateHdfsUri(String hdfsUri) {
    if (hdfsUri == null) {
      throw new IllegalArgumentException("Cluster HDFS URI can't be empty");
    }

    try {
      URI uri = new URI(hdfsUri);
      if (uri.getScheme() != null && uri.getAuthority() != null) {
        return;
      }
    } catch (URISyntaxException exception) {
      // handled below
    }
    throw new IllegalArgumentException(
        "Cluster HDFS URI should contain scheme and authority, e.g. hdfs://nameservice: "
            + hdfsUri);
  }

  private <T> T executeDbOperation(Supplier<T> operation, String errorMessage)
      throws IOException {
    try {
      return operation.get();
    } catch (DuplicateKeyException exception) {
      throw new IllegalArgumentException("Cluster with the same name already exists", exception);
    } catch (Exception exception) {
      throw logAndBuildMetastoreException(log, errorMessage, exception);
    }
  }
}
