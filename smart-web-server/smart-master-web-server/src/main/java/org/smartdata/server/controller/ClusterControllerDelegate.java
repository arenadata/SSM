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
package org.smartdata.server.controller;

import lombok.RequiredArgsConstructor;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.ClusterNodeSortField;
import org.smartdata.model.request.ClusterNodeSearchRequest;
import org.smartdata.server.cluster.ClusterNodesManager;
import org.smartdata.server.generated.api.ClusterApiDelegate;
import org.smartdata.server.generated.model.ClusterNodesDto;
import org.smartdata.server.generated.model.ClusterSortDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.RegistrationTimeIntervalDto;
import org.smartdata.server.mappers.ClusterNodeMapper;
import org.smartdata.server.mappers.pagination.ClusterNodePageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ClusterControllerDelegate implements ClusterApiDelegate {

  private final ClusterNodesManager clusterNodesManager;

  private final ClusterNodeMapper clusterNodeMapper;
  private final ClusterNodePageRequestMapper pageRequestMapper;

  @Override
  public ClusterNodesDto getClusterNodes(
      PageRequestDto pageRequestDto,
      List<ClusterSortDto> sort,
      RegistrationTimeIntervalDto registrationTime) {

    PageRequest<ClusterNodeSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    ClusterNodeSearchRequest searchRequest =
        clusterNodeMapper.toSearchRequest(registrationTime);

    return clusterNodeMapper.toClusterNodes(
        clusterNodesManager.search(searchRequest, pageRequest));
  }
}
