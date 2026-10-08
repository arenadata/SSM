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
package org.smartdata.server.mappers;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValueMappingStrategy;
import org.mapstruct.ReportingPolicy;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.request.ClusterSearchRequest;
import org.smartdata.server.generated.model.ClusterDto;
import org.smartdata.server.generated.model.ClusterRequestDto;
import org.smartdata.server.generated.model.ClusterStatusDto;
import org.smartdata.server.generated.model.ClustersDto;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ClusterMapper extends SmartMapper {

  ClusterDto toClusterDto(ClusterInfo cluster);

  ClustersDto toClustersDto(SearchResult<ClusterInfo> searchResult);

  @Mapping(target = "id", ignore = true)
  @Mapping(target = "status", ignore = true)
  @Mapping(target = "createTime", ignore = true)
  @Mapping(target = "updateTime", ignore = true)
  ClusterInfo toClusterInfo(ClusterRequestDto clusterRequest);

  @BeanMapping(nullValueMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT)
  ClusterSearchRequest toSearchRequest(String nameLike, List<ClusterStatusDto> statuses);
}
