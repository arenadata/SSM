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
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;
import javax.validation.Valid;

import java.util.List;
import java.util.Optional;

/**
 * A delegate to be called by the {@link ActionsApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface ActionsApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * GET /api/v2/actions/{id} : Get action by id
     *
     * @param id Id of the resource (required)
     * @return OK (status code 200)
     *         or Action with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see ActionsApi#getAction
     */
    default ActionDto getAction(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/actions : List all actions
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param textRepresentationLike The object&#39;s text representation filter.  May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param submissionTime Time interval in which the entity was submitted (optional)
     * @param hosts List of hosts on which the action is/was running (optional)
     * @param states List of action states (optional)
     * @param sources List of action sources (optional)
     * @param completionTime Time interval in which the action was finished (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see ActionsApi#getActions
     */
    default ActionsDto getActions(PageRequestDto pageRequest,
        List<@Valid ActionSortDto> sort,
        String textRepresentationLike,
        SubmissionTimeIntervalDto submissionTime,
        List<String> hosts,
        List<@Valid ActionStateDto> states,
        List<@Valid ActionSourceDto> sources,
        CompletionTimeIntervalDto completionTime) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * POST /api/v2/actions : Submit action
     *
     * @param submitActionRequestDto  (required)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see ActionsApi#submitAction
     */
    default ActionInfoDto submitAction(SubmitActionRequestDto submitActionRequestDto) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
