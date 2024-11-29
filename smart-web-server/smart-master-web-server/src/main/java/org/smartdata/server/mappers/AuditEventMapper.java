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
import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.request.AuditSearchRequest;
import org.smartdata.server.generated.model.AuditEventDto;
import org.smartdata.server.generated.model.AuditEventResultDto;
import org.smartdata.server.generated.model.AuditEventsDto;
import org.smartdata.server.generated.model.AuditObjectTypeDto;
import org.smartdata.server.generated.model.AuditOperationDto;
import org.smartdata.server.generated.model.EventTimeIntervalDto;

import javax.validation.Valid;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface AuditEventMapper extends SmartMapper {
  AuditEventDto toAuditEventDto(UserActivityEvent event);

  AuditEventsDto toAuditEventsDto(SearchResult<UserActivityEvent> searchResult);

  @Mapping(source = "eventTime", target = "timestampBetween")
  AuditSearchRequest toSearchRequest(
      String userLike,
      EventTimeIntervalDto eventTime,
      List<@Valid AuditObjectTypeDto> objectTypes,
      List<Long> objectIds,
      List<@Valid AuditOperationDto> operations,
      List<@Valid AuditEventResultDto> results);

  @Mapping(source = "eventTimeFrom", target = "from")
  @Mapping(source = "eventTimeTo", target = "to")
  TimeInterval toTimeInterval(EventTimeIntervalDto intervalDto);
}
