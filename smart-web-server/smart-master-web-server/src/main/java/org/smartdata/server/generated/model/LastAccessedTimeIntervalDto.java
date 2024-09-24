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
 * LastAccessedTimeIntervalDto
 */

@JsonTypeName("LastAccessedTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class LastAccessedTimeIntervalDto {

  private Long lastAccessedTimeFrom = null;

  private Long lastAccessedTimeTo = null;

  public LastAccessedTimeIntervalDto lastAccessedTimeFrom(Long lastAccessedTimeFrom) {
    this.lastAccessedTimeFrom = lastAccessedTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return lastAccessedTimeFrom
  */
  @Min(0L) 
  @Schema(name = "lastAccessedTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("lastAccessedTimeFrom")
  public Long getLastAccessedTimeFrom() {
    return lastAccessedTimeFrom;
  }

  public void setLastAccessedTimeFrom(Long lastAccessedTimeFrom) {
    this.lastAccessedTimeFrom = lastAccessedTimeFrom;
  }

  public LastAccessedTimeIntervalDto lastAccessedTimeTo(Long lastAccessedTimeTo) {
    this.lastAccessedTimeTo = lastAccessedTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return lastAccessedTimeTo
  */
  @Min(0L) 
  @Schema(name = "lastAccessedTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("lastAccessedTimeTo")
  public Long getLastAccessedTimeTo() {
    return lastAccessedTimeTo;
  }

  public void setLastAccessedTimeTo(Long lastAccessedTimeTo) {
    this.lastAccessedTimeTo = lastAccessedTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    LastAccessedTimeIntervalDto lastAccessedTimeInterval = (LastAccessedTimeIntervalDto) o;
    return Objects.equals(this.lastAccessedTimeFrom, lastAccessedTimeInterval.lastAccessedTimeFrom) &&
        Objects.equals(this.lastAccessedTimeTo, lastAccessedTimeInterval.lastAccessedTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(lastAccessedTimeFrom, lastAccessedTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class LastAccessedTimeIntervalDto {\n");
    sb.append("    lastAccessedTimeFrom: ").append(toIndentedString(lastAccessedTimeFrom)).append("\n");
    sb.append("    lastAccessedTimeTo: ").append(toIndentedString(lastAccessedTimeTo)).append("\n");
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

