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
import org.smartdata.server.generated.model.CachedFilesDto;
import org.smartdata.server.generated.model.CachedTimeIntervalDto;
import org.smartdata.server.generated.model.ErrorResponseDto;
import org.smartdata.server.generated.model.FileAccessCountsDto;
import org.smartdata.server.generated.model.LastAccessedTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
@Validated
@Tag(name = "Files", description = "the Files API")
public interface FilesApi {

    default FilesApiDelegate getDelegate() {
        return new FilesApiDelegate() {};
    }

    /**
     * GET /api/v2/files/access-counts : List access counts of files
     *
     * @param pageRequest  (optional)
     * @param pathLike The file path filter. May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param lastAccessedTime Time interval in which the file was accessed (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     */
    @Operation(
        operationId = "getAccessCounts",
        summary = "List access counts of files",
        tags = { "Files" },
        responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = FileAccessCountsDto.class))
            }),
            @ApiResponse(responseCode = "400", description = "Data is filled incorrectly", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponseDto.class))
            })
        }
    )
    @RequestMapping(
        method = RequestMethod.GET,
        value = "/api/v2/files/access-counts",
        produces = { "application/json" }
    )
    @ResponseStatus(HttpStatus.OK)
    
    default FileAccessCountsDto getAccessCounts(
        @Parameter(name = "pageRequest", description = "", in = ParameterIn.QUERY) @Valid PageRequestDto pageRequest,
        @Parameter(name = "pathLike", description = "The file path filter. May contain special characters like \"/\", \"'\", so should be encoded.", in = ParameterIn.QUERY) @Valid @RequestParam(value = "pathLike", required = false) String pathLike,
        @Parameter(name = "lastAccessedTime", description = "Time interval in which the file was accessed", in = ParameterIn.QUERY) @Valid LastAccessedTimeIntervalDto lastAccessedTime
    ) throws Exception {
        return getDelegate().getAccessCounts(pageRequest, pathLike, lastAccessedTime);
    }


    /**
     * GET /api/v2/files/cached : List cached files
     *
     * @param pageRequest  (optional)
     * @param pathLike The file path filter. May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param lastAccessedTime Time interval in which the file was accessed (optional)
     * @param cachedTime Time interval in which the file was cached (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     */
    @Operation(
        operationId = "getCachedFiles",
        summary = "List cached files",
        tags = { "Files" },
        responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = CachedFilesDto.class))
            }),
            @ApiResponse(responseCode = "400", description = "Data is filled incorrectly", content = {
                @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponseDto.class))
            })
        }
    )
    @RequestMapping(
        method = RequestMethod.GET,
        value = "/api/v2/files/cached",
        produces = { "application/json" }
    )
    @ResponseStatus(HttpStatus.OK)
    
    default CachedFilesDto getCachedFiles(
        @Parameter(name = "pageRequest", description = "", in = ParameterIn.QUERY) @Valid PageRequestDto pageRequest,
        @Parameter(name = "pathLike", description = "The file path filter. May contain special characters like \"/\", \"'\", so should be encoded.", in = ParameterIn.QUERY) @Valid @RequestParam(value = "pathLike", required = false) String pathLike,
        @Parameter(name = "lastAccessedTime", description = "Time interval in which the file was accessed", in = ParameterIn.QUERY) @Valid LastAccessedTimeIntervalDto lastAccessedTime,
        @Parameter(name = "cachedTime", description = "Time interval in which the file was cached", in = ParameterIn.QUERY) @Valid CachedTimeIntervalDto cachedTime
    ) throws Exception {
        return getDelegate().getCachedFiles(pageRequest, pathLike, lastAccessedTime, cachedTime);
    }

}
