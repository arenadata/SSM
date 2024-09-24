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
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.RulesInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.RuleSearchRequest;
import org.smartdata.server.generated.model.LastActivationTimeIntervalDto;
import org.smartdata.server.generated.model.RuleDto;
import org.smartdata.server.generated.model.RuleStateDto;
import org.smartdata.server.generated.model.RulesDto;
import org.smartdata.server.generated.model.RulesInfoDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface RuleInfoMapper extends SmartMapper {
  @Mapping(source = "ruleText", target = "textRepresentation")
  @Mapping(source = "numCmdsGen", target = "cmdletsGenerated")
  @Mapping(source = "numChecked", target = "activationCount")
  @Mapping(source = "lastCheckTime",
      target = "lastActivationTime",
      qualifiedByName = "lastActivationTime")
  RuleDto toRuleDto(RuleInfo event);

  RulesDto toRulesDto(SearchResult<RuleInfo> searchResult);

  @Mapping(target = "state", ignore = true)
  @Mapping(target = "ids", ignore = true)
  @Mapping(target = "id", ignore = true)
  @Mapping(target = "includeDeletedRules", constant = "false")
  RuleSearchRequest toSearchRequest(
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<RuleStateDto> states,
      LastActivationTimeIntervalDto lastActivationTime);

  RulesInfoDto toRulesInfoDto(RulesInfo rulesInfo);

  default List<RuleState> toRuleStates(List<RuleStateDto> states) {
    return states == null
        ? Collections.emptyList()
        : states.stream()
        .flatMap(this::toRuleStates)
        .collect(Collectors.toList());
  }

  default Stream<RuleState> toRuleStates(RuleStateDto state) {
    if (state == RuleStateDto.ACTIVE) {
      return Stream.of(RuleState.ACTIVE);
    }

    return Stream.of(
        RuleState.NEW,
        RuleState.DISABLED,
        RuleState.FINISHED);
  }

  default RuleStateDto toRuleStateDto(RuleState state) {
    return state == RuleState.ACTIVE
        ? RuleStateDto.ACTIVE
        : RuleStateDto.DISABLED;
  }

  @Named("lastActivationTime")
  default Long toLastActivationTime(long lastCheckTime) {
    return lastCheckTime == 0 ? null : lastCheckTime;
  }

  @Mapping(source = "submissionTimeFrom", target = "from")
  @Mapping(source = "submissionTimeTo", target = "to")
  TimeInterval toTimeInterval(SubmissionTimeIntervalDto intervalDto);

  @Mapping(source = "lastActivationTimeFrom", target = "from")
  @Mapping(source = "lastActivationTimeTo", target = "to")
  TimeInterval toTimeInterval(LastActivationTimeIntervalDto intervalDto);
}
