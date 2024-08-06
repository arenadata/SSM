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
package org.smartdata.server.cluster;

import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.queries.sort.ClusterNodeSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.model.request.ClusterNodeSearchRequest;
import org.smartdata.server.SearchableInMemoryService;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.cmdlet.HazelcastExecutorService;
import org.smartdata.server.engine.cmdlet.agent.AgentExecutorService;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class ClusterNodesManager extends SearchableInMemoryService<
    ClusterNodeSearchRequest, NodeCmdletMetrics, ClusterNodeSortField> {

  private final AgentExecutorService agentService;
  private final HazelcastExecutorService hazelcastService;
  private final ClusterNodeMetricsProvider nodeMetricsProvider;

  public ClusterNodesManager(
      SmartConf conf, CmdletManager cmdletManager) throws IOException {
    this(new AgentExecutorService(conf, cmdletManager),
        new HazelcastExecutorService(cmdletManager), cmdletManager);
    cmdletManager.registerExecutorService(agentService);
    cmdletManager.registerExecutorService(hazelcastService);
  }

  public ClusterNodesManager(
      AgentExecutorService agentExecutorService,
      HazelcastExecutorService hazelcastService,
      ClusterNodeMetricsProvider nodeMetricsProvider) {
    this.nodeMetricsProvider = nodeMetricsProvider;
    this.agentService = agentExecutorService;
    this.hazelcastService = hazelcastService;
  }

  @Override
  protected Stream<NodeCmdletMetrics> allEntitiesStream() {
    return nodeMetricsProvider.getNodeMetrics().stream();
  }

  @Override
  protected List<Predicate<NodeCmdletMetrics>> entityFilters(
      ClusterNodeSearchRequest searchRequest) {

    Predicate<Long> timeIntervalPredicate =
        timeIntervalPredicate(searchRequest.getRegistrationTime());

    return Collections.singletonList(
        node -> timeIntervalPredicate.test(node.getRegistTime())
    );
  }

  @Override
  protected Comparator<NodeCmdletMetrics> sortingToComparator(
      Sorting<ClusterNodeSortField> sorting) {
    Comparator<NodeCmdletMetrics> comparator = null;
    switch (sorting.getColumn()) {
      case ID:
        comparator = Comparator.comparing(
            NodeCmdletMetrics::getNodeInfo,
            Comparator.comparing(NodeInfo::getId));
        break;
      case EXECUTORS:
        comparator = Comparator.comparingInt(
            NodeCmdletMetrics::getNumExecutors);
        break;
      case REGISTRATION_TIME:
        comparator = Comparator.comparingLong(
            NodeCmdletMetrics::getRegistTime);
    }

    return sorting.getOrder() == Sorting.Order.DESC
        ? comparator.reversed()
        : comparator;
  }

}
