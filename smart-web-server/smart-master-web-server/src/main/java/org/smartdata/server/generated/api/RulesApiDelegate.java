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

import org.smartdata.server.generated.model.LastActivationTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.generated.model.RuleDto;
import org.smartdata.server.generated.model.RuleSortDto;
import org.smartdata.server.generated.model.RuleStateDto;
import org.smartdata.server.generated.model.RulesDto;
import org.smartdata.server.generated.model.RulesInfoDto;
import org.smartdata.server.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.server.generated.model.SubmitRuleRequestDto;
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;
import javax.validation.Valid;

import java.util.List;
import java.util.Optional;

/**
 * A delegate to be called by the {@link RulesApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface RulesApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * POST /api/v2/rules : Submit rule
     *
     * @param submitRuleRequestDto  (required)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see RulesApi#addRule
     */
    default RuleDto addRule(SubmitRuleRequestDto submitRuleRequestDto) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * DELETE /api/v2/rules/{id} : Delete rule by id
     *
     * @param id Id of the resource (required)
     * @return Rule has been removed (status code 200)
     *         or Rule with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see RulesApi#deleteRule
     */
    default void deleteRule(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/rules/{id} : Get rule by id
     *
     * @param id Id of the resource (required)
     * @return OK (status code 200)
     *         or Rule with specified id not found (status code 404)
     *         or Unauthorized (status code 401)
     * @see RulesApi#getRule
     */
    default RuleDto getRule(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/rules : List all rules
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param textRepresentationLike The object&#39;s text representation filter.  May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param submissionTime Time interval in which the entity was submitted (optional)
     * @param ruleStates List of rule states (optional)
     * @param lastActivationTime Time interval in which the rule was activated (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see RulesApi#getRules
     */
    default RulesDto getRules(PageRequestDto pageRequest,
        List<@Valid RuleSortDto> sort,
        String textRepresentationLike,
        SubmissionTimeIntervalDto submissionTime,
        List<@Valid RuleStateDto> ruleStates,
        LastActivationTimeIntervalDto lastActivationTime) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/rules/info : Get information about rules
     *
     * @return OK (status code 200)
     *         or Unauthorized (status code 401)
     * @see RulesApi#getRulesInfo
     */
    default RulesInfoDto getRulesInfo() throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * POST /api/v2/rules/{id}/start : Start or continue specified rule
     *
     * @param id Id of the resource (required)
     * @return Rule has been started (status code 200)
     *         or Rule with specified id not found (status code 404)
     *         or Unsupported state transition (status code 400)
     *         or Unauthorized (status code 401)
     * @see RulesApi#startRule
     */
    default void startRule(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * POST /api/v2/rules/{id}/stop : Stop specified rule
     *
     * @param id Id of the resource (required)
     * @return Rule has been stopped (status code 200)
     *         or Rule with specified id not found (status code 404)
     *         or Unsupported state transition (status code 400)
     *         or Unauthorized (status code 401)
     * @see RulesApi#stopRule
     */
    default void stopRule(Long id) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
