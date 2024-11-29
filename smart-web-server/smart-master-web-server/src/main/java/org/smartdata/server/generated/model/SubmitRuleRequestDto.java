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
 * SubmitRuleRequestDto
 */

@JsonTypeName("SubmitRuleRequest")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class SubmitRuleRequestDto {

  private String rule;

  public SubmitRuleRequestDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public SubmitRuleRequestDto(String rule) {
    this.rule = rule;
  }

  public SubmitRuleRequestDto rule(String rule) {
    this.rule = rule;
    return this;
  }

  /**
   * Rule text representation
   * @return rule
  */
  @NotNull 
  @Schema(name = "rule", description = "Rule text representation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("rule")
  public String getRule() {
    return rule;
  }

  public void setRule(String rule) {
    this.rule = rule;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SubmitRuleRequestDto submitRuleRequest = (SubmitRuleRequestDto) o;
    return Objects.equals(this.rule, submitRuleRequest.rule);
  }

  @Override
  public int hashCode() {
    return Objects.hash(rule);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SubmitRuleRequestDto {\n");
    sb.append("    rule: ").append(toIndentedString(rule)).append("\n");
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

