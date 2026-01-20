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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.smartdata.server.generated.model.ActionsMetadataDto;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.annotation.Generated;

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
@Validated
@Tag(name = "Metadata", description = "the Metadata API")
public interface MetadataApi {

  default MetadataApiDelegate getDelegate() {
    return new MetadataApiDelegate() {
    };
  }

  /**
   * GET /api/v2/metadata/actions : List all actions metadata
   *
   * @return OK (status code 200)
   *         or Unauthorized (status code 401)
   */
  @Operation(
      operationId = "getActionsMetadata",
      summary = "List all actions metadata",
      tags = {"Metadata"},
      responses = {
          @ApiResponse(responseCode = "200", description = "OK", content = {
              @Content(mediaType = "application/json", schema = @Schema(implementation = ActionsMetadataDto.class))
          }),
          @ApiResponse(responseCode = "401", description = "Unauthorized")
      },
      security = {
          @SecurityRequirement(name = "basicAuth")
      }
  )
  @RequestMapping(
      method = RequestMethod.GET,
      value = "/api/v2/metadata/actions",
      produces = {"application/json"}
  )
  @ResponseStatus(HttpStatus.OK)

  default ActionsMetadataDto getActionsMetadata(

  ) throws Exception {
    return getDelegate().getActionsMetadata();
  }

}
