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

import org.mapstruct.Condition;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import org.mapstruct.ValueMapping;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.CmdletSearchRequest;
import org.smartdata.server.generated.model.CmdletDto;
import org.smartdata.server.generated.model.CmdletStateDto;
import org.smartdata.server.generated.model.CmdletsDto;
import org.smartdata.server.generated.model.StateChangeTimeIntervalDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface CmdletInfoMapper extends SmartMapper {
  @Mapping(source = "ruleId", target = "ruleId", conditionQualifiedByName = "isValidRuleId")
  @Mapping(source = "parameters", target = "textRepresentation")
  @Mapping(source = "generateTime", target = "submissionTime")
  CmdletDto toCmdletDto(CmdletInfo cmdletInfo);

  CmdletsDto toCmdletsDto(SearchResult<CmdletInfo> searchResult);

  @ValueMapping(source = "NOTINITED", target = "NOT_INITED")
  @ValueMapping(source = "PAUSED", target = "DISABLED")
  CmdletStateDto toCmdletDtoState(CmdletState cmdletState);

  @ValueMapping(source = "NOT_INITED", target = "NOTINITED")
  CmdletState toCmdletState(CmdletStateDto cmdletState);

  @Mapping(target = "ids", ignore = true)
  @Mapping(target = "state", ignore = true)
  @Mapping(target = "ruleId", ignore = true)
  @Mapping(target = "id", ignore = true)
  CmdletSearchRequest toSearchRequest(
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<Long> ruleIds,
      List<CmdletStateDto> states,
      StateChangeTimeIntervalDto stateChangedTime);

  @Mapping(source = "submissionTimeFrom", target = "from")
  @Mapping(source = "submissionTimeTo", target = "to")
  TimeInterval toTimeInterval(SubmissionTimeIntervalDto intervalDto);

  @Mapping(source = "stateChangedTimeFrom", target = "from")
  @Mapping(source = "stateChangedTimeTo", target = "to")
  TimeInterval toTimeInterval(StateChangeTimeIntervalDto intervalDto);

  // rule ids sequence always starts from 1, but in the future consider to
  // todo refactor cmdlets related logic to make ruleId (rid) nullable
  @Condition
  @Named("isValidRuleId")
  static boolean isValidRuleId(long ruleId) {
    return ruleId > 0;
  }
}
