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
package org.smartdata.server.generated.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * CmdletDto
 */

@JsonTypeName("Cmdlet")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class CmdletDto {

  private Long id;

  private Long ruleId = null;

  @Valid
  private List<Long> actionIds = new ArrayList<>();

  private CmdletStateDto state;

  private String textRepresentation;

  private Long submissionTime;

  private Long stateChangedTime;

  public CmdletDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public CmdletDto(Long id, List<Long> actionIds, CmdletStateDto state, String textRepresentation, Long submissionTime, Long stateChangedTime) {
    this.id = id;
    this.actionIds = actionIds;
    this.state = state;
    this.textRepresentation = textRepresentation;
    this.submissionTime = submissionTime;
    this.stateChangedTime = stateChangedTime;
  }

  public CmdletDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Cmdlet id
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "Cmdlet id", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public CmdletDto ruleId(Long ruleId) {
    this.ruleId = ruleId;
    return this;
  }

  /**
   * Id of the rule that generated cmdlet
   * @return ruleId
  */
  
  @Schema(name = "ruleId", description = "Id of the rule that generated cmdlet", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("ruleId")
  public Long getRuleId() {
    return ruleId;
  }

  public void setRuleId(Long ruleId) {
    this.ruleId = ruleId;
  }

  public CmdletDto actionIds(List<Long> actionIds) {
    this.actionIds = actionIds;
    return this;
  }

  public CmdletDto addActionIdsItem(Long actionIdsItem) {
    if (this.actionIds == null) {
      this.actionIds = new ArrayList<>();
    }
    this.actionIds.add(actionIdsItem);
    return this;
  }

  /**
   * List of the action ids belonging to the current cmdlet
   * @return actionIds
  */
  @NotNull 
  @Schema(name = "actionIds", description = "List of the action ids belonging to the current cmdlet", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("actionIds")
  public List<Long> getActionIds() {
    return actionIds;
  }

  public void setActionIds(List<Long> actionIds) {
    this.actionIds = actionIds;
  }

  public CmdletDto state(CmdletStateDto state) {
    this.state = state;
    return this;
  }

  /**
   * Get state
   * @return state
  */
  @NotNull @Valid 
  @Schema(name = "state", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("state")
  public CmdletStateDto getState() {
    return state;
  }

  public void setState(CmdletStateDto state) {
    this.state = state;
  }

  public CmdletDto textRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
    return this;
  }

  /**
   * Cmdlet text representation
   * @return textRepresentation
  */
  @NotNull 
  @Schema(name = "textRepresentation", description = "Cmdlet text representation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("textRepresentation")
  public String getTextRepresentation() {
    return textRepresentation;
  }

  public void setTextRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
  }

  public CmdletDto submissionTime(Long submissionTime) {
    this.submissionTime = submissionTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the cmdlet submission
   * @return submissionTime
  */
  @NotNull 
  @Schema(name = "submissionTime", description = "UNIX timestamp (UTC) of the cmdlet submission", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("submissionTime")
  public Long getSubmissionTime() {
    return submissionTime;
  }

  public void setSubmissionTime(Long submissionTime) {
    this.submissionTime = submissionTime;
  }

  public CmdletDto stateChangedTime(Long stateChangedTime) {
    this.stateChangedTime = stateChangedTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the cmdlet state modification
   * @return stateChangedTime
  */
  @NotNull 
  @Schema(name = "stateChangedTime", description = "UNIX timestamp (UTC) of the cmdlet state modification", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("stateChangedTime")
  public Long getStateChangedTime() {
    return stateChangedTime;
  }

  public void setStateChangedTime(Long stateChangedTime) {
    this.stateChangedTime = stateChangedTime;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CmdletDto cmdlet = (CmdletDto) o;
    return Objects.equals(this.id, cmdlet.id) &&
        Objects.equals(this.ruleId, cmdlet.ruleId) &&
        Objects.equals(this.actionIds, cmdlet.actionIds) &&
        Objects.equals(this.state, cmdlet.state) &&
        Objects.equals(this.textRepresentation, cmdlet.textRepresentation) &&
        Objects.equals(this.submissionTime, cmdlet.submissionTime) &&
        Objects.equals(this.stateChangedTime, cmdlet.stateChangedTime);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, ruleId, actionIds, state, textRepresentation, submissionTime, stateChangedTime);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CmdletDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    ruleId: ").append(toIndentedString(ruleId)).append("\n");
    sb.append("    actionIds: ").append(toIndentedString(actionIds)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
    sb.append("    textRepresentation: ").append(toIndentedString(textRepresentation)).append("\n");
    sb.append("    submissionTime: ").append(toIndentedString(submissionTime)).append("\n");
    sb.append("    stateChangedTime: ").append(toIndentedString(stateChangedTime)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}

