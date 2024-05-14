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
import javax.annotation.Generated;
import javax.validation.Valid;
import org.smartdata.server.generated.model.ClusterNodesDto;
import org.smartdata.server.generated.model.ErrorResponseDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.RegistrationTimeIntervalDto;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
@Validated
@Tag(name = "Cluster", description = "the Cluster API")
public interface ClusterApi {

    default ClusterApiDelegate getDelegate() {
        return new ClusterApiDelegate() {};
    }

    /**
     * GET /api/v2/cluster/nodes : List all cluster nodes
     *
     * @param pageRequest  (optional)
     * @param registrationTime Time interval in which node was registered in master (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     */
    @Operation(
        operationId = "getClusterNodes",
        summary = "List all cluster nodes",
        tags = { "Cluster" },
        responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = ClusterNodesDto.class))
            }),
            @ApiResponse(responseCode = "400", description = "Data is filled incorrectly", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponseDto.class))
            })
        }
    )
    @RequestMapping(
        method = RequestMethod.GET,
        value = "/api/v2/cluster/nodes",
        produces = { "application/json" }
    )
    @ResponseStatus(HttpStatus.OK)
    
    default ClusterNodesDto getClusterNodes(
        @Parameter(name = "pageRequest", description = "", in = ParameterIn.QUERY) @Valid PageRequestDto pageRequest,
        @Parameter(name = "registrationTime", description = "Time interval in which node was registered in master", in = ParameterIn.QUERY) @Valid RegistrationTimeIntervalDto registrationTime
    ) throws Exception {
        return getDelegate().getClusterNodes(pageRequest, registrationTime);
    }

}
