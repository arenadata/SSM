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
 * ActionInfoDto
 */

@JsonTypeName("ActionInfo")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class ActionInfoDto {

  private Long id;

  private Long cmdletId;

  private String textRepresentation;

  private String execHost = null;

  private Long submissionTime;

  private Long completionTime = null;

  private ActionStateDto state;

  private ActionSourceDto source;

  public ActionInfoDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public ActionInfoDto(Long id, Long cmdletId, String textRepresentation, Long submissionTime, ActionStateDto state, ActionSourceDto source) {
    this.id = id;
    this.cmdletId = cmdletId;
    this.textRepresentation = textRepresentation;
    this.submissionTime = submissionTime;
    this.state = state;
    this.source = source;
  }

  public ActionInfoDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Action id
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "Action id", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public ActionInfoDto cmdletId(Long cmdletId) {
    this.cmdletId = cmdletId;
    return this;
  }

  /**
   * Id of the cmdlet this action belongs to
   * @return cmdletId
  */
  @NotNull 
  @Schema(name = "cmdletId", description = "Id of the cmdlet this action belongs to", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("cmdletId")
  public Long getCmdletId() {
    return cmdletId;
  }

  public void setCmdletId(Long cmdletId) {
    this.cmdletId = cmdletId;
  }

  public ActionInfoDto textRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
    return this;
  }

  /**
   * Action text representation
   * @return textRepresentation
  */
  @NotNull 
  @Schema(name = "textRepresentation", description = "Action text representation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("textRepresentation")
  public String getTextRepresentation() {
    return textRepresentation;
  }

  public void setTextRepresentation(String textRepresentation) {
    this.textRepresentation = textRepresentation;
  }

  public ActionInfoDto execHost(String execHost) {
    this.execHost = execHost;
    return this;
  }

  /**
   * SSM host on which this action is running
   * @return execHost
  */
  
  @Schema(name = "execHost", description = "SSM host on which this action is running", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("execHost")
  public String getExecHost() {
    return execHost;
  }

  public void setExecHost(String execHost) {
    this.execHost = execHost;
  }

  public ActionInfoDto submissionTime(Long submissionTime) {
    this.submissionTime = submissionTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the action submission
   * @return submissionTime
  */
  @NotNull 
  @Schema(name = "submissionTime", description = "UNIX timestamp (UTC) of the action submission", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("submissionTime")
  public Long getSubmissionTime() {
    return submissionTime;
  }

  public void setSubmissionTime(Long submissionTime) {
    this.submissionTime = submissionTime;
  }

  public ActionInfoDto completionTime(Long completionTime) {
    this.completionTime = completionTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the action completion
   * @return completionTime
  */
  
  @Schema(name = "completionTime", description = "UNIX timestamp (UTC) of the action completion", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("completionTime")
  public Long getCompletionTime() {
    return completionTime;
  }

  public void setCompletionTime(Long completionTime) {
    this.completionTime = completionTime;
  }

  public ActionInfoDto state(ActionStateDto state) {
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
  public ActionStateDto getState() {
    return state;
  }

  public void setState(ActionStateDto state) {
    this.state = state;
  }

  public ActionInfoDto source(ActionSourceDto source) {
    this.source = source;
    return this;
  }

  /**
   * Get source
   * @return source
  */
  @NotNull @Valid 
  @Schema(name = "source", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("source")
  public ActionSourceDto getSource() {
    return source;
  }

  public void setSource(ActionSourceDto source) {
    this.source = source;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ActionInfoDto actionInfo = (ActionInfoDto) o;
    return Objects.equals(this.id, actionInfo.id) &&
        Objects.equals(this.cmdletId, actionInfo.cmdletId) &&
        Objects.equals(this.textRepresentation, actionInfo.textRepresentation) &&
        Objects.equals(this.execHost, actionInfo.execHost) &&
        Objects.equals(this.submissionTime, actionInfo.submissionTime) &&
        Objects.equals(this.completionTime, actionInfo.completionTime) &&
        Objects.equals(this.state, actionInfo.state) &&
        Objects.equals(this.source, actionInfo.source);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, cmdletId, textRepresentation, execHost, submissionTime, completionTime, state, source);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ActionInfoDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    cmdletId: ").append(toIndentedString(cmdletId)).append("\n");
    sb.append("    textRepresentation: ").append(toIndentedString(textRepresentation)).append("\n");
    sb.append("    execHost: ").append(toIndentedString(execHost)).append("\n");
    sb.append("    submissionTime: ").append(toIndentedString(submissionTime)).append("\n");
    sb.append("    completionTime: ").append(toIndentedString(completionTime)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
    sb.append("    source: ").append(toIndentedString(source)).append("\n");
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

