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

import lombok.extern.slf4j.Slf4j;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.StateTransitionException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.dao.ReplicationPolicyDao;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.ReplicationPolicySortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.replication.ReplicationPoliciesInfo;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationPolicyStatus;
import org.smartdata.model.request.ReplicationPolicySearchRequest;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.server.engine.ClusterListener;
import org.smartdata.server.engine.ClusterManager;
import org.smartdata.server.engine.HiveCatalogManager;
import org.smartdata.server.engine.audit.AuditService;
import org.smartdata.server.engine.audit.Auditable;
import org.smartdata.server.engine.audit.aspect.Audit;
import org.smartdata.server.engine.audit.aspect.AuditId;
import org.smartdata.server.engine.audit.aspect.ReturnsAuditId;
import org.springframework.dao.DuplicateKeyException;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import static org.smartdata.metastore.utils.MetaStoreUtils.logAndBuildMetastoreException;
import static org.smartdata.model.audit.UserActivityObject.REPLICATION_POLICY;
import static org.smartdata.model.audit.UserActivityOperation.CREATE;
import static org.smartdata.model.audit.UserActivityOperation.DELETE;
import static org.smartdata.model.audit.UserActivityOperation.START;
import static org.smartdata.model.audit.UserActivityOperation.STOP;
import static org.smartdata.model.replication.ReplicationPolicyStatus.ACTIVE;
import static org.smartdata.model.replication.ReplicationPolicyStatus.COMPLETED;
import static org.smartdata.model.replication.ReplicationPolicyStatus.CREATED;
import static org.smartdata.model.replication.ReplicationPolicyStatus.PAUSED;

/**
 * Manages the replication policies. Listens to the changes of the target clusters
 * to prevent breaking the policies.
 */
@Slf4j
public class ReplicationPolicyManager implements ClusterListener, Auditable {
  private final ReplicationPolicyDao policyDao;
  private final ReplicationPolicyValidator validator;
  private final AuditService auditService;
  private final SmartPrincipalManager principalManager;
  private final Searchable<ReplicationPolicySearchRequest, ReplicationPolicyInfo,
      ReplicationPolicySortField> searchService;
  private final Clock clock;

  public ReplicationPolicyManager(
      MetaStore metaStore,
      ClusterManager clusterManager,
      HiveCatalogManager hiveCatalogManager,
      AuditService auditService,
      SmartPrincipalManager principalManager) {
    this(metaStore.replicationPolicyDao(), clusterManager, hiveCatalogManager,
        auditService, principalManager, Clock.systemUTC());
  }

  public ReplicationPolicyManager(
      ReplicationPolicyDao policyDao,
      ClusterManager clusterManager,
      HiveCatalogManager hiveCatalogManager,
      AuditService auditService,
      SmartPrincipalManager principalManager,
      Clock clock) {
    this.policyDao = policyDao;
    this.validator = new ReplicationPolicyValidator(clusterManager, hiveCatalogManager);
    this.auditService = auditService;
    this.principalManager = principalManager;
    this.searchService = new SearchableService<>(policyDao, "replication policies");
    this.clock = clock;
  }

  public SearchResult<ReplicationPolicyInfo> search(
      ReplicationPolicySearchRequest searchRequest,
      PageRequest<ReplicationPolicySortField> pageRequest) throws IOException {
    return searchService.search(searchRequest, pageRequest);
  }

  public ReplicationPolicyInfo getPolicy(long id) throws IOException {
    return executeDbOperation(() -> policyDao.getById(id), "Error fetching policy " + id)
        .orElseThrow(() -> NotFoundException.forIdentifiableEntity("Replication policy", id));
  }

  public ReplicationPoliciesInfo getPoliciesInfo() throws IOException {
    return executeDbOperation(policyDao::getPoliciesInfo, "Error fetching policies info");
  }

  public List<String> getTags() throws IOException {
    return executeDbOperation(policyDao::getTags, "Error fetching policy tags");
  }

  /**
   * Creates the policy in the {@link ReplicationPolicyStatus#CREATED} status.
   *
   * @param policy policy settings. Id, status and timestamps are ignored.
   */
  public ReplicationPolicyInfo createPolicy(ReplicationPolicyInfo policy) throws IOException {
    return getPolicy(insertPolicy(policy));
  }

  @ReturnsAuditId
  @Audit(objectType = REPLICATION_POLICY, operation = CREATE)
  private long insertPolicy(ReplicationPolicyInfo policy) throws IOException {
    Instant now = clock.instant();
    ReplicationPolicyInfo newPolicy = validator.validate(ReplicationPolicyInfo.builder()
            .status(CREATED)
            .createTime(now)
            .updateTime(now)
            .build(), policy);

    // TODO generate the policy rules in the same transaction with the policy creation:
    //  - ADH-9536: hms-sync rule per source database, if the metadata replication is enabled;
    //  - ADH-9537: sync rule per non-overlapping source root directory, collected from the
    //    Hive catalog locations of the selected entities, if the data replication is enabled.
    return executeDbOperation(
        () -> policyDao.insert(newPolicy), "Error creating policy " + newPolicy.getName());
  }

  /**
   * Updates settings of the policy, which isn't {@link ReplicationPolicyStatus#COMPLETED completed}.
   *
   * @param policy new policy settings. Id, status and timestamps are ignored.
   */
  public ReplicationPolicyInfo updatePolicy(long id, ReplicationPolicyInfo policy)
      throws IOException {
    ReplicationPolicyInfo oldPolicy = getPolicy(id);
    if (oldPolicy.getStatus() == COMPLETED) {
      throw new StateTransitionException("Completed replication policy can't be updated: " + id);
    }

    ReplicationPolicyInfo updatedPolicy = validator.validate(oldPolicy, policy)
        .toBuilder()
        .updateTime(clock.instant())
        .build();

    // TODO ADH-9536, ADH-9537 update the policy rules keeping their state:
    //  - if only the replication settings are changed (events, preserved attributes,
    //    cascade, schedule), then disable the rules, update their text and restore the state,
    //    so that the hms-sync rules keep their progress;
    //  - if the replication scope is changed (target cluster, databases, tables),
    //    then delete the obsolete rules and generate the new ones.
    update(updatedPolicy);
    return updatedPolicy;
  }

  /**
   * Launches the created or resumes the paused policy.
   */
  @Audit(objectType = REPLICATION_POLICY, operation = START)
  public void startPolicy(@AuditId long id) throws IOException {
    // TODO ADH-9536, ADH-9537: activate the policy rules
    changeStatus(id, EnumSet.of(CREATED, PAUSED), ACTIVE);
  }

  @Audit(objectType = REPLICATION_POLICY, operation = STOP)
  public void pausePolicy(@AuditId long id) throws IOException {
    // TODO ADH-9536, ADH-9537: disable the policy rules dropping their pending cmdlets
    changeStatus(id, EnumSet.of(ACTIVE), PAUSED);
  }

  /**
   * Finishes the policy, after which it can't be launched or modified anymore.
   */
  @Audit(objectType = REPLICATION_POLICY, operation = DELETE)
  public void completePolicy(@AuditId long id) throws IOException {
    // TODO ADH-9536, ADH-9537: delete the policy rules dropping their pending cmdlets
    changeStatus(id, EnumSet.of(CREATED, ACTIVE, PAUSED), COMPLETED);
  }

  /**
   * Prevents removing Hive Thrift URI used for the metadata replication.
   */
  @Override
  public void beforeClusterUpdate(ClusterInfo oldCluster, ClusterInfo newCluster)
      throws IOException {
    if (newCluster.getHiveThriftUri() == null) {
      List<ReplicationPolicyInfo> metadataReplicationPolicies =
          getNotCompletedPolicies(newCluster.getId()).stream()
              .filter(policy -> policy.getMetadataReplication().isEnabled())
              .collect(Collectors.toList());
      if (!metadataReplicationPolicies.isEmpty()) {
        throw new IllegalArgumentException(
            "Hive Thrift URI can't be removed, because it's used for the metadata replication "
                + "by the policies: " + policyNames(metadataReplicationPolicies));
      }
    }

    // TODO update rules of the cluster policies if the cluster URIs
    //  or HDFS nameservice are changed
  }

  /**
   * Prevents completing the cluster, which is used by the not completed policies.
   */
  @Override
  public void beforeClusterComplete(ClusterInfo cluster) throws IOException {
    List<ReplicationPolicyInfo> policies = getNotCompletedPolicies(cluster.getId());
    if (!policies.isEmpty()) {
      throw new StateTransitionException(
          "Cluster can't be completed until its replication policies are completed: "
              + policyNames(policies));
    }
  }

  @Override
  public AuditService getAuditService() {
    return auditService;
  }

  @Override
  public SmartPrincipalManager getPrincipalService() {
    return principalManager;
  }

  private List<ReplicationPolicyInfo> getNotCompletedPolicies(long clusterId) throws IOException {
    ReplicationPolicySearchRequest searchRequest = ReplicationPolicySearchRequest.builder()
        .targetClusterIds(Collections.singletonList(clusterId))
        .statuses(Arrays.asList(CREATED, ACTIVE, PAUSED))
        .build();
    return searchService.search(searchRequest);
  }

  private static List<String> policyNames(List<ReplicationPolicyInfo> policies) {
    return policies.stream()
        .map(ReplicationPolicyInfo::getName)
        .collect(Collectors.toList());
  }

  private void changeStatus(
      long id,
      Set<ReplicationPolicyStatus> allowedStatuses,
      ReplicationPolicyStatus newStatus) throws IOException {
    ReplicationPolicyInfo policy = getPolicy(id);
    if (!allowedStatuses.contains(policy.getStatus())) {
      throw StateTransitionException.forReplicationPolicy(policy.getStatus(), newStatus);
    }

    update(policy.toBuilder()
        .status(newStatus)
        .updateTime(clock.instant())
        .build());
  }

  private void update(ReplicationPolicyInfo policy) throws IOException {
    boolean updated = executeDbOperation(
        () -> policyDao.update(policy), "Error updating policy " + policy.getId());
    if (!updated) {
      throw NotFoundException.forIdentifiableEntity("Replication policy", policy.getId());
    }
  }

  private <T> T executeDbOperation(Callable<T> operation, String errorMessage)
      throws IOException {
    try {
      return operation.call();
    } catch (DuplicateKeyException exception) {
      throw new IllegalArgumentException(
          "Replication policy with the same name already exists", exception);
    } catch (Exception exception) {
      throw logAndBuildMetastoreException(log, errorMessage, exception);
    }
  }
}
