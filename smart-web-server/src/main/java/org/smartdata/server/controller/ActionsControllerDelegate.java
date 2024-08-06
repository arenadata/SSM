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
import org.smartdata.metastore.queries.sort.ActionSortField;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.request.ActionSearchRequest;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.action.ActionInfoHandler;
import org.smartdata.server.generated.api.ActionsApiDelegate;
import org.smartdata.server.generated.model.ActionDto;
import org.smartdata.server.generated.model.ActionInfoDto;
import org.smartdata.server.generated.model.ActionSortDto;
import org.smartdata.server.generated.model.ActionSourceDto;
import org.smartdata.server.generated.model.ActionStateDto;
import org.smartdata.server.generated.model.ActionsDto;
import org.smartdata.server.generated.model.CompletionTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmitActionRequestDto;
import org.smartdata.server.mappers.ActionInfoMapper;
import org.smartdata.server.mappers.pagination.ActionPageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ActionsControllerDelegate implements ActionsApiDelegate {

  private final ActionInfoHandler actionInfoHandler;
  private final CmdletManager cmdletManager;

  private final ActionInfoMapper actionInfoMapper;
  private final ActionPageRequestMapper pageRequestMapper;

  @Override
  public ActionDto getAction(Long id) throws Exception {
    return actionInfoMapper.toActionDto(
        actionInfoHandler.getActionInfo(id));
  }

  @Override
  public ActionsDto getActions(
      PageRequestDto pageRequestDto,
      List<ActionSortDto> actionSort,
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<String> hosts,
      List<ActionStateDto> states,
      List<ActionSourceDto> sources,
      CompletionTimeIntervalDto completionTime) {

    PageRequest<ActionSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, actionSort);

    ActionSearchRequest searchRequest = actionInfoMapper.toSearchRequest(
        textRepresentationLike, submissionTime, hosts, states, sources, completionTime);

    SearchResult<ActionInfo> searchResult =
        actionInfoHandler.search(searchRequest, pageRequest);

    return actionInfoMapper.toActionsDto(searchResult);
  }

  @Override
  public ActionInfoDto submitAction(
      SubmitActionRequestDto submitActionRequestDto) throws Exception {
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet(
        submitActionRequestDto.getAction());

    ActionInfo actionInfo = cmdletManager.getCmdletInfoHandler()
        .getSingleActionInfo(cmdletInfo.getId());
    return actionInfoMapper.toActionInfoDto(actionInfo);
  }
}
