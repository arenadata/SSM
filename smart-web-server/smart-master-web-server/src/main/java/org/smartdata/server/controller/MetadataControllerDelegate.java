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
import org.smartdata.action.ActionMetadata;
import org.smartdata.action.ActionRegistry;
import org.smartdata.server.generated.api.MetadataApiDelegate;
import org.smartdata.server.generated.model.ActionsMetadataDto;
import org.smartdata.server.mappers.ActionMetadataMapper;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class MetadataControllerDelegate implements MetadataApiDelegate {

  private final ActionRegistry actionRegistry;
  private final ActionMetadataMapper actionMetadataMapper;

  @Override
  public ActionsMetadataDto getActionsMetadata() {
    Set<ActionMetadata> actionMetadata = actionRegistry.getActionMetadata();
    return actionMetadataMapper.toActionsMetadataDto(actionMetadata);
  }
}
