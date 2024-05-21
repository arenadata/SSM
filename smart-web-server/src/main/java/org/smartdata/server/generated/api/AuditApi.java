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
/**
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech) (7.3.0).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
package org.smartdata.server.generated.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import javax.annotation.Generated;
import javax.validation.Valid;
import org.smartdata.server.generated.model.AuditEventResultDto;
import org.smartdata.server.generated.model.AuditEventsDto;
import org.smartdata.server.generated.model.AuditObjectTypeDto;
import org.smartdata.server.generated.model.AuditOperationDto;
import org.smartdata.server.generated.model.AuditSortDto;
import org.smartdata.server.generated.model.ErrorResponseDto;
import org.smartdata.server.generated.model.EventTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
@Validated
@Tag(name = "Audit", description = "the Audit API")
public interface AuditApi {

    default AuditApiDelegate getDelegate() {
        return new AuditApiDelegate() {};
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
     */
    @Operation(
        operationId = "getAuditEvents",
        summary = "List all audit events",
        tags = { "Audit" },
        responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = AuditEventsDto.class))
            }),
            @ApiResponse(responseCode = "400", description = "Data is filled incorrectly", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponseDto.class))
            })
        }
    )
    @RequestMapping(
        method = RequestMethod.GET,
        value = "/api/v2/audit/events",
        produces = { "application/json" }
    )
    @ResponseStatus(HttpStatus.OK)
    
    default AuditEventsDto getAuditEvents(
        @Parameter(name = "pageRequest", description = "", in = ParameterIn.QUERY) @Valid PageRequestDto pageRequest,
        @Parameter(name = "sort", description = "Sort field names prefixed with '-' for descending order", in = ParameterIn.QUERY) @Valid @RequestParam(value = "sort", required = false) List<@Valid AuditSortDto> sort,
        @Parameter(name = "usernameLike", description = "Filter of the name of the user who performed the event", in = ParameterIn.QUERY) @Valid @RequestParam(value = "usernameLike", required = false) String usernameLike,
        @Parameter(name = "eventTime", description = "Time interval in which the event occurred", in = ParameterIn.QUERY) @Valid EventTimeIntervalDto eventTime,
        @Parameter(name = "objectTypes", description = "List of audit object types", in = ParameterIn.QUERY) @Valid @RequestParam(value = "objectTypes", required = false) List<@Valid AuditObjectTypeDto> objectTypes,
        @Parameter(name = "objectIds", description = "Ids of the event objects", in = ParameterIn.QUERY) @Valid @RequestParam(value = "objectIds", required = false) List<Long> objectIds,
        @Parameter(name = "operations", description = "List of audit operations", in = ParameterIn.QUERY) @Valid @RequestParam(value = "operations", required = false) List<@Valid AuditOperationDto> operations,
        @Parameter(name = "results", description = "List of audit event results", in = ParameterIn.QUERY) @Valid @RequestParam(value = "results", required = false) List<@Valid AuditEventResultDto> results
    ) throws Exception {
        return getDelegate().getAuditEvents(pageRequest, sort, usernameLike, eventTime, objectTypes, objectIds, operations, results);
    }

}
