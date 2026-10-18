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
import org.mapstruct.MappingConstants;
import org.mapstruct.NullValueMappingStrategy;
import org.mapstruct.ReportingPolicy;
import org.mapstruct.ValueMapping;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.replication.ReplicationPoliciesInfo;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.request.ReplicationPolicySearchRequest;
import org.smartdata.server.generated.model.DataReplicationEventDto;
import org.smartdata.server.generated.model.MetadataReplicationEventDto;
import org.smartdata.server.generated.model.ReplicationPoliciesDto;
import org.smartdata.server.generated.model.ReplicationPoliciesInfoDto;
import org.smartdata.server.generated.model.ReplicationPolicyDto;
import org.smartdata.server.generated.model.ReplicationPolicyRequestDto;
import org.smartdata.server.generated.model.ReplicationPolicyStatusDto;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ReplicationPolicyMapper extends SmartMapper {

  ReplicationPolicyDto toPolicyDto(ReplicationPolicyInfo policy);

  ReplicationPoliciesDto toPoliciesDto(SearchResult<ReplicationPolicyInfo> searchResult);

  ReplicationPoliciesInfoDto toPoliciesInfoDto(ReplicationPoliciesInfo policiesInfo);

  @Mapping(target = "id", ignore = true)
  @Mapping(target = "status", ignore = true)
  @Mapping(target = "createTime", ignore = true)
  @Mapping(target = "updateTime", ignore = true)
  ReplicationPolicyInfo toPolicyInfo(ReplicationPolicyRequestDto policyRequest);

  @BeanMapping(nullValueMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT)
  ReplicationPolicySearchRequest toSearchRequest(
      String nameLike,
      List<ReplicationPolicyStatusDto> statuses,
      List<Long> targetClusterIds);

  // only filterable diff types are stored in the policies
  @ValueMapping(source = MappingConstants.ANY_REMAINING, target = MappingConstants.THROW_EXCEPTION)
  DataReplicationEventDto toDataReplicationEventDto(FileDiffType diffType);

  // only filterable operations are stored in the policies
  @ValueMapping(source = MappingConstants.ANY_REMAINING, target = MappingConstants.THROW_EXCEPTION)
  MetadataReplicationEventDto toMetadataReplicationEventDto(HiveOperation operation);
}
