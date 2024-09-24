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

import javax.annotation.Generated;
import javax.validation.constraints.NotNull;

import java.util.Objects;

/**
 * RulesInfoDto
 */

@JsonTypeName("RulesInfo")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class RulesInfoDto {

  private Long totalRules;

  private Long activeRules;

  public RulesInfoDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public RulesInfoDto(Long totalRules, Long activeRules) {
    this.totalRules = totalRules;
    this.activeRules = activeRules;
  }

  public RulesInfoDto totalRules(Long totalRules) {
    this.totalRules = totalRules;
    return this;
  }

  /**
   * Total number of rules
   * @return totalRules
   */
  @NotNull
  @Schema(name = "totalRules", description = "Total number of rules", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("totalRules")
  public Long getTotalRules() {
    return totalRules;
  }

  public void setTotalRules(Long totalRules) {
    this.totalRules = totalRules;
  }

  public RulesInfoDto activeRules(Long activeRules) {
    this.activeRules = activeRules;
    return this;
  }

  /**
   * Number of active rules
   * @return activeRules
   */
  @NotNull
  @Schema(name = "activeRules", description = "Number of active rules", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("activeRules")
  public Long getActiveRules() {
    return activeRules;
  }

  public void setActiveRules(Long activeRules) {
    this.activeRules = activeRules;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RulesInfoDto rulesInfo = (RulesInfoDto) o;
    return Objects.equals(this.totalRules, rulesInfo.totalRules) &&
        Objects.equals(this.activeRules, rulesInfo.activeRules);
  }

  @Override
  public int hashCode() {
    return Objects.hash(totalRules, activeRules);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RulesInfoDto {\n");
    sb.append("    totalRules: ").append(toIndentedString(totalRules)).append("\n");
    sb.append("    activeRules: ").append(toIndentedString(activeRules)).append("\n");
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

