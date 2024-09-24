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
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * RuleDto
 */

@JsonTypeName("Rule")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class RuleDto {

  private Long id;

  private Long submitTime;

  private String textRepresentation;

  private RuleStateDto state;

  private Long activationCount;

  private Long cmdletsGenerated;

  private Long lastActivationTime = null;

  public RuleDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public RuleDto(Long id, Long submitTime, String textRepresentation, RuleStateDto state, Long activationCount, Long cmdletsGenerated) {
    this.id = id;
    this.submitTime = submitTime;
    this.textRepresentation = textRepresentation;
    this.state = state;
    this.activationCount = activationCount;
    this.cmdletsGenerated = cmdletsGenerated;
  }

  public RuleDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Rule id
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "Rule id", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public RuleDto submitTime(Long submitTime) {
    this.submitTime = submitTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the rule submission
   * @return submitTime
  */
  @NotNull 
  @Schema(name = "submitTime", description = "UNIX timestamp (UTC) of the rule submission", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("submitTime")
  public Long getSubmitTime() {
    return submitTime;
  }

  public void setSubmitTime(Long submitTime) {
    this.submitTime = submitTime;
  }

  public RuleDto textRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
    return this;
  }

  /**
   * Rule text representation
   * @return textRepresentation
  */
  @NotNull 
  @Schema(name = "textRepresentation", description = "Rule text representation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("textRepresentation")
  public String getTextRepresentation() {
    return textRepresentation;
  }

  public void setTextRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
  }

  public RuleDto state(RuleStateDto state) {
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
  public RuleStateDto getState() {
    return state;
  }

  public void setState(RuleStateDto state) {
    this.state = state;
  }

  public RuleDto activationCount(Long activationCount) {
    this.activationCount = activationCount;
    return this;
  }

  /**
   * Number of rule activations
   * @return activationCount
  */
  @NotNull 
  @Schema(name = "activationCount", description = "Number of rule activations", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("activationCount")
  public Long getActivationCount() {
    return activationCount;
  }

  public void setActivationCount(Long activationCount) {
    this.activationCount = activationCount;
  }

  public RuleDto cmdletsGenerated(Long cmdletsGenerated) {
    this.cmdletsGenerated = cmdletsGenerated;
    return this;
  }

  /**
   * Number of generated cmdlets from this rule
   * @return cmdletsGenerated
  */
  @NotNull 
  @Schema(name = "cmdletsGenerated", description = "Number of generated cmdlets from this rule", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("cmdletsGenerated")
  public Long getCmdletsGenerated() {
    return cmdletsGenerated;
  }

  public void setCmdletsGenerated(Long cmdletsGenerated) {
    this.cmdletsGenerated = cmdletsGenerated;
  }

  public RuleDto lastActivationTime(Long lastActivationTime) {
    this.lastActivationTime = lastActivationTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the last rule activation
   * @return lastActivationTime
  */
  
  @Schema(name = "lastActivationTime", description = "UNIX timestamp (UTC) of the last rule activation", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("lastActivationTime")
  public Long getLastActivationTime() {
    return lastActivationTime;
  }

  public void setLastActivationTime(Long lastActivationTime) {
    this.lastActivationTime = lastActivationTime;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RuleDto rule = (RuleDto) o;
    return Objects.equals(this.id, rule.id) &&
        Objects.equals(this.submitTime, rule.submitTime) &&
        Objects.equals(this.textRepresentation, rule.textRepresentation) &&
        Objects.equals(this.state, rule.state) &&
        Objects.equals(this.activationCount, rule.activationCount) &&
        Objects.equals(this.cmdletsGenerated, rule.cmdletsGenerated) &&
        Objects.equals(this.lastActivationTime, rule.lastActivationTime);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, submitTime, textRepresentation, state, activationCount, cmdletsGenerated, lastActivationTime);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RuleDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    submitTime: ").append(toIndentedString(submitTime)).append("\n");
    sb.append("    textRepresentation: ").append(toIndentedString(textRepresentation)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
    sb.append("    activationCount: ").append(toIndentedString(activationCount)).append("\n");
    sb.append("    cmdletsGenerated: ").append(toIndentedString(cmdletsGenerated)).append("\n");
    sb.append("    lastActivationTime: ").append(toIndentedString(lastActivationTime)).append("\n");
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

