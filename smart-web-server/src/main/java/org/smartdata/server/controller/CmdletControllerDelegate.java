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
import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.request.CmdletSearchRequest;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.cmdlet.CmdletInfoHandler;
import org.smartdata.server.generated.api.CmdletsApiDelegate;
import org.smartdata.server.generated.model.CmdletDto;
import org.smartdata.server.generated.model.CmdletSortDto;
import org.smartdata.server.generated.model.CmdletStateDto;
import org.smartdata.server.generated.model.CmdletsDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.StateChangeTimeIntervalDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmitCmdletRequestDto;
import org.smartdata.server.mappers.CmdletInfoMapper;
import org.smartdata.server.mappers.pagination.CmdletsPageRequestMapper;
import org.springframework.stereotype.Component;

import javax.validation.Valid;

import java.util.List;

@Component
@RequiredArgsConstructor
public class CmdletControllerDelegate implements CmdletsApiDelegate {

  private final CmdletInfoHandler cmdletInfoHandler;
  private final CmdletManager cmdletManager;

  private final CmdletInfoMapper cmdletInfoMapper;
  private final CmdletsPageRequestMapper pageRequestMapper;

  @Override
  public CmdletDto addCmdlet(
      SubmitCmdletRequestDto submitCmdletRequestDto) throws Exception {
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet(
        submitCmdletRequestDto.getCmdlet());
    return cmdletInfoMapper.toCmdletDto(cmdletInfo);
  }

  @Override
  public void deleteCmdlet(Long id) throws Exception {
    cmdletManager.deleteCmdlet(id);
  }

  @Override
  public CmdletsDto getCmdlets(
      PageRequestDto pageRequestDto,
      List<@Valid CmdletSortDto> sort,
      String textRepresentationLike,
      SubmissionTimeIntervalDto submissionTime,
      List<Long> ruleIds,
      List<CmdletStateDto> states,
      StateChangeTimeIntervalDto stateChangedTime) throws Exception {

    CmdletSearchRequest searchRequest = cmdletInfoMapper.toSearchRequest(
        textRepresentationLike, submissionTime, ruleIds, states, stateChangedTime);

    PageRequest<CmdletSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    return cmdletInfoMapper.toCmdletsDto(
        cmdletInfoHandler.search(searchRequest, pageRequest));
  }

  @Override
  public void stopCmdlet(Long id) throws Exception {
    cmdletManager.disableCmdlet(id);
  }

  @Override
  public CmdletDto getCmdlet(Long id) throws Exception {
    CmdletInfo cmdletInfo = cmdletInfoHandler.getCmdletInfoOrThrow(id);
    return cmdletInfoMapper.toCmdletDto(cmdletInfo);
  }
}
