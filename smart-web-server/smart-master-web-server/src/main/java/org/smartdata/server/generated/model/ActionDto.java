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
 * ActionDto
 */

@JsonTypeName("Action")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class ActionDto {

  private Long id;

  private Long cmdletId;

  private String textRepresentation;

  private String execHost = null;

  private Long submissionTime;

  private Long completionTime = null;

  private ActionStateDto state;

  private ActionSourceDto source;

  private String log;

  public ActionDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public ActionDto(Long id, Long cmdletId, String textRepresentation, Long submissionTime, ActionStateDto state, ActionSourceDto source) {
    this.id = id;
    this.cmdletId = cmdletId;
    this.textRepresentation = textRepresentation;
    this.submissionTime = submissionTime;
    this.state = state;
    this.source = source;
  }

  public ActionDto id(Long id) {
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

  public ActionDto cmdletId(Long cmdletId) {
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

  public ActionDto textRepresentation(String textRepresentation) {
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

  public ActionDto execHost(String execHost) {
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

  public ActionDto submissionTime(Long submissionTime) {
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

  public ActionDto completionTime(Long completionTime) {
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

  public ActionDto state(ActionStateDto state) {
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

  public ActionDto source(ActionSourceDto source) {
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

  public ActionDto log(String log) {
    this.log = log;
    return this;
  }

  /**
   * Action log
   * @return log
  */
  
  @Schema(name = "log", description = "Action log", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("log")
  public String getLog() {
    return log;
  }

  public void setLog(String log) {
    this.log = log;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ActionDto action = (ActionDto) o;
    return Objects.equals(this.id, action.id) &&
        Objects.equals(this.cmdletId, action.cmdletId) &&
        Objects.equals(this.textRepresentation, action.textRepresentation) &&
        Objects.equals(this.execHost, action.execHost) &&
        Objects.equals(this.submissionTime, action.submissionTime) &&
        Objects.equals(this.completionTime, action.completionTime) &&
        Objects.equals(this.state, action.state) &&
        Objects.equals(this.source, action.source) &&
        Objects.equals(this.log, action.log);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, cmdletId, textRepresentation, execHost, submissionTime, completionTime, state, source, log);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ActionDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    cmdletId: ").append(toIndentedString(cmdletId)).append("\n");
    sb.append("    textRepresentation: ").append(toIndentedString(textRepresentation)).append("\n");
    sb.append("    execHost: ").append(toIndentedString(execHost)).append("\n");
    sb.append("    submissionTime: ").append(toIndentedString(submissionTime)).append("\n");
    sb.append("    completionTime: ").append(toIndentedString(completionTime)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
    sb.append("    source: ").append(toIndentedString(source)).append("\n");
    sb.append("    log: ").append(toIndentedString(log)).append("\n");
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

