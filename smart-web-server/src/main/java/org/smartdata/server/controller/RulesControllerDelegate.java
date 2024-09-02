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
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.RuleSortField;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RulesInfo;
import org.smartdata.model.request.RuleSearchRequest;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.generated.api.RulesApiDelegate;
import org.smartdata.server.generated.model.LastActivationTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.RuleDto;
import org.smartdata.server.generated.model.RuleSortDto;
import org.smartdata.server.generated.model.RuleStateDto;
import org.smartdata.server.generated.model.RulesDto;
import org.smartdata.server.generated.model.RulesInfoDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmitRuleRequestDto;
import org.smartdata.server.mappers.RuleInfoMapper;
import org.smartdata.server.mappers.pagination.RulesPageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class RulesControllerDelegate implements RulesApiDelegate {

  private final RuleManager ruleManager;

  private final RuleInfoMapper ruleInfoMapper;
  private final RulesPageRequestMapper pageRequestMapper;

  @Override
  public RuleDto addRule(SubmitRuleRequestDto submitRuleRequestDto) throws Exception {
    RuleInfo ruleInfo = ruleManager.submitRule(submitRuleRequestDto.getRule());
    return ruleInfoMapper.toRuleDto(ruleInfo);
  }

  @Override
  public void deleteRule(Long id) throws Exception {
    ruleManager.deleteRule(id, false);
  }

  @Override
  public RuleDto getRule(Long id) throws Exception {
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    return ruleInfoMapper.toRuleDto(ruleInfo);
  }

  @Override
  public RulesDto getRules(
      PageRequestDto pageRequestDto,
      List<RuleSortDto> sort,
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<RuleStateDto> ruleStates,
      LastActivationTimeIntervalDto lastActivationTime) throws Exception {

    PageRequest<RuleSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    RuleSearchRequest searchRequest = ruleInfoMapper.toSearchRequest(
        textRepresentationLike, submissionTime, ruleStates, lastActivationTime);

    SearchResult<RuleInfo> searchResult = ruleManager.search(searchRequest, pageRequest);
    return ruleInfoMapper.toRulesDto(searchResult);
  }

  @Override
  public RulesInfoDto getRulesInfo() throws Exception {
    RulesInfo rulesInfo = ruleManager.getRulesInfo();
    return ruleInfoMapper.toRulesInfoDto(rulesInfo);
  }

  @Override
  public void startRule(Long id) throws Exception {
    ruleManager.activateRule(id);
  }

  @Override
  public void stopRule(Long id) throws Exception {
    ruleManager.disableRule(id, true);
  }
}
