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
package org.smartdata.server;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.dao.SearchableTestSupport;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.ClusterNodeSortField;
import org.smartdata.model.ExecutorType;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.ClusterNodeSearchRequest;
import org.smartdata.server.cluster.ClusterNodesManager;
import org.smartdata.server.cluster.NodeCmdletMetrics;
import org.smartdata.server.cluster.NodeInfo;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public class ClusterNodesManagerTest {
  private static final String FIRST_NODE_ID = "1.one";
  private static final String SECOND_NODE_ID = "2.two";
  private static final String THIRD_NODE_ID = "3.three";

  private SearchableTestSupport<ClusterNodeSearchRequest, NodeCmdletMetrics,
      ClusterNodeSortField, String> searchableTestSupport;

  @Before
  public void initCmdletManager() {
    ClusterNodesManager clusterNodesManager = new ClusterNodesManager(
        null, null, this::nodeCmdletMetrics);
    searchableTestSupport = new SearchableTestSupport<>(
        clusterNodesManager, ClusterNodeSortField.ID, this::getNodeId);
  }

  @Test
  public void testSearchWithoutFilters() {
    searchableTestSupport.testSearch(ClusterNodeSearchRequest.noFilters(),
        FIRST_NODE_ID, SECOND_NODE_ID, THIRD_NODE_ID);
  }

  @Test
  public void testSearchByRegistrationTime() {
    ClusterNodeSearchRequest searchRequest = ClusterNodeSearchRequest.builder()
        .registrationTime(new TimeInterval(
            Instant.EPOCH, Instant.ofEpochMilli(1000)))
        .build();

    searchableTestSupport.testSearch(searchRequest,
        FIRST_NODE_ID, SECOND_NODE_ID, THIRD_NODE_ID);

    searchRequest = ClusterNodeSearchRequest.builder()
        .registrationTime(new TimeInterval(
            Instant.ofEpochMilli(6), Instant.ofEpochMilli(12)))
        .build();

    searchableTestSupport.testSearch(searchRequest, THIRD_NODE_ID);

    searchRequest = ClusterNodeSearchRequest.builder()
        .registrationTime(new TimeInterval(
            Instant.ofEpochMilli(13), Instant.ofEpochMilli(1000)))
        .build();

    searchableTestSupport.testSearch(searchRequest);
  }

  @Test
  public void testSortById() {
    testSortBy(ClusterNodeSortField.ID,
        FIRST_NODE_ID, SECOND_NODE_ID, THIRD_NODE_ID);
  }

  @Test
  public void testSortByRegistrationTime() {
    testSortBy(ClusterNodeSortField.REGISTRATION_TIME,
        FIRST_NODE_ID, SECOND_NODE_ID, THIRD_NODE_ID);
  }

  @Test
  public void testSortByExecutors() {
    testSortBy(ClusterNodeSortField.EXECUTORS,
        SECOND_NODE_ID, THIRD_NODE_ID, FIRST_NODE_ID);
  }

  private void testSortBy(ClusterNodeSortField sortField, String... ascendingIds) {
    PageRequest<ClusterNodeSortField> pageRequest = PageRequest.<ClusterNodeSortField>builder()
        .sortByAsc(sortField)
        .build();

    searchableTestSupport.testPagedSearch(
        ClusterNodeSearchRequest.noFilters(), pageRequest, ascendingIds);

    pageRequest = PageRequest.<ClusterNodeSortField>builder()
        .sortByDesc(sortField)
        .build();

    ArrayUtils.reverse(ascendingIds);
    searchableTestSupport.testPagedSearch(
        ClusterNodeSearchRequest.noFilters(), pageRequest, ascendingIds);
  }

  private Collection<NodeCmdletMetrics> nodeCmdletMetrics() {
    NodeCmdletMetrics node1 = NodeCmdletMetrics.builder()
        .nodeInfo(NodeInfo.builder()
            .id(FIRST_NODE_ID)
            .executorType(ExecutorType.LOCAL)
            .build())
        .numExecutors(13)
        .registTime(0)
        .build();

    NodeCmdletMetrics node2 = NodeCmdletMetrics.builder()
        .nodeInfo(NodeInfo.builder()
            .id(SECOND_NODE_ID)
            .executorType(ExecutorType.REMOTE_SSM)
            .build())
        .numExecutors(4)
        .registTime(5)
        .build();

    NodeCmdletMetrics node3 = NodeCmdletMetrics.builder()
        .nodeInfo(NodeInfo.builder()
            .id(THIRD_NODE_ID)
            .executorType(ExecutorType.AGENT)
            .build())
        .numExecutors(8)
        .registTime(12)
        .build();

    return Arrays.asList(node1, node2, node3);
  }

  private String getNodeId(NodeCmdletMetrics metrics) {
    return Optional.ofNullable(metrics)
        .map(NodeCmdletMetrics::getNodeInfo)
        .map(NodeInfo::getId)
        .orElse(null);
  }
}
