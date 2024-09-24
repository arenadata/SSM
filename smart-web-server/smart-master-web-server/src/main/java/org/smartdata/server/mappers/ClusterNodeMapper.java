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

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.ClusterNodeSearchRequest;
import org.smartdata.server.cluster.NodeCmdletMetrics;
import org.smartdata.server.generated.model.ClusterNodeDto;
import org.smartdata.server.generated.model.ClusterNodesDto;
import org.smartdata.server.generated.model.RegistrationTimeIntervalDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ClusterNodeMapper extends SmartMapper {

  @Mapping(source = "registTime", target = "registrationTime")
  @Mapping(source = "numExecutors", target = "executorsCount")
  @Mapping(source = "nodeInfo.port", target = "port")
  @Mapping(source = "nodeInfo.id", target = "id")
  @Mapping(source = "nodeInfo.host", target = "host")
  @Mapping(source = "nodeInfo.executorType", target = "executorType")
  ClusterNodeDto toClusterNodeDto(NodeCmdletMetrics metrics);

  ClusterNodesDto toClusterNodes(SearchResult<NodeCmdletMetrics> searchResult);

  ClusterNodeSearchRequest toSearchRequest(
      RegistrationTimeIntervalDto registrationTime);

  @Mapping(source = "registrationTimeFrom", target = "from")
  @Mapping(source = "registrationTimeTo", target = "to")
  TimeInterval toTimeInterval(RegistrationTimeIntervalDto intervalDto);
}
