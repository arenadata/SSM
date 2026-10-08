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
import org.smartdata.metastore.queries.sort.ReplicationPolicySortField;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.request.ReplicationPolicySearchRequest;
import org.smartdata.server.engine.replication.ReplicationPolicyManager;
import org.smartdata.server.generated.api.ReplicationPoliciesApiDelegate;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.ReplicationPoliciesDto;
import org.smartdata.server.generated.model.ReplicationPoliciesInfoDto;
import org.smartdata.server.generated.model.ReplicationPolicyDto;
import org.smartdata.server.generated.model.ReplicationPolicyRequestDto;
import org.smartdata.server.generated.model.ReplicationPolicySortDto;
import org.smartdata.server.generated.model.ReplicationPolicyStatusDto;
import org.smartdata.server.mappers.ReplicationPolicyMapper;
import org.smartdata.server.mappers.pagination.ReplicationPolicyPageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ReplicationPoliciesControllerDelegate implements ReplicationPoliciesApiDelegate {

  private final ReplicationPolicyManager policyManager;

  private final ReplicationPolicyMapper policyMapper;
  private final ReplicationPolicyPageRequestMapper pageRequestMapper;

  @Override
  public ReplicationPoliciesDto getReplicationPolicies(
      PageRequestDto pageRequestDto,
      List<ReplicationPolicySortDto> sort,
      String nameLike,
      List<ReplicationPolicyStatusDto> statuses,
      List<Long> targetClusterIds) throws Exception {
    PageRequest<ReplicationPolicySortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    ReplicationPolicySearchRequest searchRequest =
        policyMapper.toSearchRequest(nameLike, statuses, targetClusterIds);

    return policyMapper.toPoliciesDto(policyManager.search(searchRequest, pageRequest));
  }

  @Override
  public ReplicationPolicyDto getReplicationPolicy(Long id) throws Exception {
    return policyMapper.toPolicyDto(policyManager.getPolicy(id));
  }

  @Override
  public ReplicationPoliciesInfoDto getReplicationPoliciesInfo() throws Exception {
    return policyMapper.toPoliciesInfoDto(policyManager.getPoliciesInfo());
  }

  @Override
  public List<String> getReplicationPolicyTags() throws Exception {
    return policyManager.getTags();
  }

  @Override
  public ReplicationPolicyDto createReplicationPolicy(
      ReplicationPolicyRequestDto policyRequestDto) throws Exception {
    ReplicationPolicyInfo policy = policyMapper.toPolicyInfo(policyRequestDto);
    return policyMapper.toPolicyDto(policyManager.createPolicy(policy));
  }

  @Override
  public ReplicationPolicyDto updateReplicationPolicy(
      Long id, ReplicationPolicyRequestDto policyRequestDto) throws Exception {
    ReplicationPolicyInfo policy = policyMapper.toPolicyInfo(policyRequestDto);
    return policyMapper.toPolicyDto(policyManager.updatePolicy(id, policy));
  }

  @Override
  public void startReplicationPolicy(Long id) throws Exception {
    policyManager.startPolicy(id);
  }

  @Override
  public void pauseReplicationPolicy(Long id) throws Exception {
    policyManager.pausePolicy(id);
  }

  @Override
  public void completeReplicationPolicy(Long id) throws Exception {
    policyManager.completePolicy(id);
  }
}
