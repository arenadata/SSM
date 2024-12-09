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
import javax.validation.constraints.Min;

import java.util.Objects;

/**
 * StartTimeIntervalDto
 */

@JsonTypeName("StartTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class StartTimeIntervalDto {

  private Long startTimeFrom = null;

  private Long startTimeTo = null;

  public StartTimeIntervalDto startTimeFrom(Long startTimeFrom) {
    this.startTimeFrom = startTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return startTimeFrom
   */
  @Min(0L)
  @Schema(name = "startTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("startTimeFrom")
  public Long getStartTimeFrom() {
    return startTimeFrom;
  }

  public void setStartTimeFrom(Long startTimeFrom) {
    this.startTimeFrom = startTimeFrom;
  }

  public StartTimeIntervalDto startTimeTo(Long startTimeTo) {
    this.startTimeTo = startTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return startTimeTo
   */
  @Min(0L)
  @Schema(name = "startTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("startTimeTo")
  public Long getStartTimeTo() {
    return startTimeTo;
  }

  public void setStartTimeTo(Long startTimeTo) {
    this.startTimeTo = startTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    StartTimeIntervalDto startTimeInterval = (StartTimeIntervalDto) o;
    return Objects.equals(this.startTimeFrom, startTimeInterval.startTimeFrom) &&
        Objects.equals(this.startTimeTo, startTimeInterval.startTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(startTimeFrom, startTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class StartTimeIntervalDto {\n");
    sb.append("    startTimeFrom: ").append(toIndentedString(startTimeFrom)).append("\n");
    sb.append("    startTimeTo: ").append(toIndentedString(startTimeTo)).append("\n");
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

