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
import javax.validation.constraints.NotNull;

/**
 * SubmitCmdletRequestDto
 */

@JsonTypeName("SubmitCmdletRequest")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class SubmitCmdletRequestDto {

  private String cmdlet;

  public SubmitCmdletRequestDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public SubmitCmdletRequestDto(String cmdlet) {
    this.cmdlet = cmdlet;
  }

  public SubmitCmdletRequestDto cmdlet(String cmdlet) {
    this.cmdlet = cmdlet;
    return this;
  }

  /**
   * Cmdlet text representation
   * @return cmdlet
  */
  @NotNull 
  @Schema(name = "cmdlet", description = "Cmdlet text representation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("cmdlet")
  public String getCmdlet() {
    return cmdlet;
  }

  public void setCmdlet(String cmdlet) {
    this.cmdlet = cmdlet;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SubmitCmdletRequestDto submitCmdletRequest = (SubmitCmdletRequestDto) o;
    return Objects.equals(this.cmdlet, submitCmdletRequest.cmdlet);
  }

  @Override
  public int hashCode() {
    return Objects.hash(cmdlet);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SubmitCmdletRequestDto {\n");
    sb.append("    cmdlet: ").append(toIndentedString(cmdlet)).append("\n");
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

