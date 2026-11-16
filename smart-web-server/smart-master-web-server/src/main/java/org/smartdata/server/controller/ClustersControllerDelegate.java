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
import org.smartdata.metastore.queries.sort.ClusterSortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.request.ClusterSearchRequest;
import org.smartdata.server.engine.ClusterManager;
import org.smartdata.server.generated.api.ClustersApiDelegate;
import org.smartdata.server.generated.model.ClusterDto;
import org.smartdata.server.generated.model.ClusterRequestDto;
import org.smartdata.server.generated.model.ClusterSortDto;
import org.smartdata.server.generated.model.ClusterStatusDto;
import org.smartdata.server.generated.model.ClustersDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.mappers.ClusterMapper;
import org.smartdata.server.mappers.pagination.ClusterPageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ClustersControllerDelegate implements ClustersApiDelegate {

  private final ClusterManager clusterManager;

  private final ClusterMapper clusterMapper;
  private final ClusterPageRequestMapper pageRequestMapper;

  @Override
  public ClustersDto getClusters(
      PageRequestDto pageRequestDto,
      List<ClusterSortDto> sort,
      String nameLike,
      List<ClusterStatusDto> statuses) throws Exception {
    PageRequest<ClusterSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    ClusterSearchRequest searchRequest = clusterMapper.toSearchRequest(nameLike, statuses);

    return clusterMapper.toClustersDto(
        clusterManager.search(searchRequest, pageRequest));
  }

  @Override
  public ClusterDto getCluster(Long id) throws Exception {
    return clusterMapper.toClusterDto(clusterManager.getCluster(id));
  }

  @Override
  public ClusterDto createCluster(ClusterRequestDto clusterRequestDto) throws Exception {
    ClusterInfo cluster = clusterMapper.toClusterInfo(clusterRequestDto);
    return clusterMapper.toClusterDto(clusterManager.createCluster(cluster));
  }

  @Override
  public ClusterDto updateCluster(Long id, ClusterRequestDto clusterRequestDto) throws Exception {
    ClusterInfo cluster = clusterMapper.toClusterInfo(clusterRequestDto);
    return clusterMapper.toClusterDto(clusterManager.updateCluster(id, cluster));
  }

  @Override
  public void completeCluster(Long id) throws Exception {
    clusterManager.completeCluster(id);
  }
}
