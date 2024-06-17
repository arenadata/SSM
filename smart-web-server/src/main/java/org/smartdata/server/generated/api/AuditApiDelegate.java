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
package org.smartdata.server.generated.api;

import org.smartdata.server.generated.model.AuditEventResultDto;
import org.smartdata.server.generated.model.AuditEventsDto;
import org.smartdata.server.generated.model.AuditObjectTypeDto;
import org.smartdata.server.generated.model.AuditOperationDto;
import org.smartdata.server.generated.model.AuditSortDto;
import org.smartdata.server.generated.model.EventTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;
import javax.validation.Valid;

import java.util.List;
import java.util.Optional;

/**
 * A delegate to be called by the {@link AuditApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface AuditApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * GET /api/v2/audit/events : List all audit events
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param usernameLike Filter of the name of the user who performed the event (optional)
     * @param eventTime Time interval in which the event occurred (optional)
     * @param objectTypes List of audit object types (optional)
     * @param objectIds Ids of the event objects (optional)
     * @param operations List of audit operations (optional)
     * @param results List of audit event results (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see AuditApi#getAuditEvents
     */
    default AuditEventsDto getAuditEvents(PageRequestDto pageRequest,
        List<@Valid AuditSortDto> sort,
        String usernameLike,
        EventTimeIntervalDto eventTime,
        List<@Valid AuditObjectTypeDto> objectTypes,
        List<Long> objectIds,
        List<@Valid AuditOperationDto> operations,
        List<@Valid AuditEventResultDto> results) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
