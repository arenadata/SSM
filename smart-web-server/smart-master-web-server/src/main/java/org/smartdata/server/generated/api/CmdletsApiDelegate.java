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

import org.smartdata.server.generated.model.CmdletDto;
import org.smartdata.server.generated.model.CmdletSortDto;
import org.smartdata.server.generated.model.CmdletStateDto;
import org.smartdata.server.generated.model.CmdletsDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.StateChangeTimeIntervalDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmitCmdletRequestDto;
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;
import javax.validation.Valid;

import java.util.List;
import java.util.Optional;

/**
 * A delegate to be called by the {@link CmdletsApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface CmdletsApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * POST /api/v2/cmdlets : Submit cmdlet
     *
     * @param submitCmdletRequestDto  (required)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see CmdletsApi#addCmdlet
     */
    default CmdletDto addCmdlet(SubmitCmdletRequestDto submitCmdletRequestDto) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * DELETE /api/v2/cmdlets/{id} : Delete cmdlet by id
     *
     * @param id Id of the resource (required)
     * @return Cmdlet has been removed (status code 200)
     *         or Cmdlet with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see CmdletsApi#deleteCmdlet
     */
    default void deleteCmdlet(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/cmdlets/{id} : Get cmdlet by id
     *
     * @param id Id of the resource (required)
     * @return OK (status code 200)
     *         or Cmdlet with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see CmdletsApi#getCmdlet
     */
    default CmdletDto getCmdlet(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/cmdlets : List all cmdlets
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param textRepresentationLike The object&#39;s text representation filter.  May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param submissionTime Time interval in which the entity was submitted (optional)
     * @param ruleIds Ids of the rules that cmdlets belong to (optional)
     * @param states List of cmdlet states (optional)
     * @param stateChangedTime Time interval in which the state of the cmdlet was changed (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see CmdletsApi#getCmdlets
     */
    default CmdletsDto getCmdlets(PageRequestDto pageRequest,
        List<@Valid CmdletSortDto> sort,
        String textRepresentationLike,
        SubmissionTimeIntervalDto submissionTime,
        List<Long> ruleIds,
        List<@Valid CmdletStateDto> states,
        StateChangeTimeIntervalDto stateChangedTime) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * POST /api/v2/cmdlets/{id}/stop : Stop specified cmdlet
     *
     * @param id Id of the resource (required)
     * @return Cmdlet has been stopped (status code 200)
     *         or Cmdlet with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see CmdletsApi#stopCmdlet
     */
    default void stopCmdlet(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
