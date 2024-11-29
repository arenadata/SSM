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
import javax.validation.constraints.Min;

/**
 * CompletionTimeIntervalDto
 */

@JsonTypeName("CompletionTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class CompletionTimeIntervalDto {

  private Long completionTimeFrom = null;

  private Long completionTimeTo = null;

  public CompletionTimeIntervalDto completionTimeFrom(Long completionTimeFrom) {
    this.completionTimeFrom = completionTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return completionTimeFrom
  */
  @Min(0L) 
  @Schema(name = "completionTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("completionTimeFrom")
  public Long getCompletionTimeFrom() {
    return completionTimeFrom;
  }

  public void setCompletionTimeFrom(Long completionTimeFrom) {
    this.completionTimeFrom = completionTimeFrom;
  }

  public CompletionTimeIntervalDto completionTimeTo(Long completionTimeTo) {
    this.completionTimeTo = completionTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return completionTimeTo
  */
  @Min(0L) 
  @Schema(name = "completionTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("completionTimeTo")
  public Long getCompletionTimeTo() {
    return completionTimeTo;
  }

  public void setCompletionTimeTo(Long completionTimeTo) {
    this.completionTimeTo = completionTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CompletionTimeIntervalDto completionTimeInterval = (CompletionTimeIntervalDto) o;
    return Objects.equals(this.completionTimeFrom, completionTimeInterval.completionTimeFrom) &&
        Objects.equals(this.completionTimeTo, completionTimeInterval.completionTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(completionTimeFrom, completionTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CompletionTimeIntervalDto {\n");
    sb.append("    completionTimeFrom: ").append(toIndentedString(completionTimeFrom)).append("\n");
    sb.append("    completionTimeTo: ").append(toIndentedString(completionTimeTo)).append("\n");
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

