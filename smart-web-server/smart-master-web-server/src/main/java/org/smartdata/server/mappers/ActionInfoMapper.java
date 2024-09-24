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
import org.smartdata.model.ActionInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.ActionSearchRequest;
import org.smartdata.server.generated.model.ActionDto;
import org.smartdata.server.generated.model.ActionInfoDto;
import org.smartdata.server.generated.model.ActionSourceDto;
import org.smartdata.server.generated.model.ActionStateDto;
import org.smartdata.server.generated.model.ActionsDto;
import org.smartdata.server.generated.model.CompletionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ActionInfoMapper extends SmartMapper {
  @Mapping(source = ".", target = "state")
  @Mapping(source = "actionText", target = "textRepresentation")
  @Mapping(source = "createTime", target = "submissionTime")
  @Mapping(source = "actionId", target = "id")
  @Mapping(source = "finishTime", target = "completionTime")
  ActionInfoDto toActionInfoDto(ActionInfo event);

  @Mapping(source = ".", target = "state")
  @Mapping(source = "actionText", target = "textRepresentation")
  @Mapping(source = "createTime", target = "submissionTime")
  @Mapping(source = "actionId", target = "id")
  @Mapping(source = "finishTime", target = "completionTime")
  ActionDto toActionDto(ActionInfo event);

  ActionsDto toActionsDto(SearchResult<ActionInfo> searchResult);

  @Mapping(target = "ids", ignore = true)
  @Mapping(target = "id", ignore = true)
  @Mapping(target = "host", ignore = true)
  @Mapping(target = "state", ignore = true)
  @Mapping(target = "source", ignore = true)
  ActionSearchRequest toSearchRequest(
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<String> hosts,
      List<ActionStateDto> states,
      List<ActionSourceDto> sources,
      CompletionTimeIntervalDto completionTime);

  @Mapping(source = "submissionTimeFrom", target = "from")
  @Mapping(source = "submissionTimeTo", target = "to")
  TimeInterval toTimeInterval(SubmissionTimeIntervalDto intervalDto);

  @Mapping(source = "completionTimeFrom", target = "from")
  @Mapping(source = "completionTimeTo", target = "to")
  TimeInterval toTimeInterval(CompletionTimeIntervalDto intervalDto);

  default ActionStateDto toActionState(ActionInfo actionInfo) {
    if (!actionInfo.isFinished()) {
      return ActionStateDto.RUNNING;
    }

    return actionInfo.isSuccessful()
        ? ActionStateDto.SUCCESSFUL
        : ActionStateDto.FAILED;
  }
}
