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
 * CachedTimeIntervalDto
 */

@JsonTypeName("CachedTimeInterval")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class CachedTimeIntervalDto {

  private Long cachedTimeFrom = null;

  private Long cachedTimeTo = null;

  public CachedTimeIntervalDto cachedTimeFrom(Long cachedTimeFrom) {
    this.cachedTimeFrom = cachedTimeFrom;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval start
   * minimum: 0
   * @return cachedTimeFrom
  */
  @Min(0L) 
  @Schema(name = "cachedTimeFrom", description = "UNIX timestamp (UTC) of the interval start", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("cachedTimeFrom")
  public Long getCachedTimeFrom() {
    return cachedTimeFrom;
  }

  public void setCachedTimeFrom(Long cachedTimeFrom) {
    this.cachedTimeFrom = cachedTimeFrom;
  }

  public CachedTimeIntervalDto cachedTimeTo(Long cachedTimeTo) {
    this.cachedTimeTo = cachedTimeTo;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the interval end
   * minimum: 0
   * @return cachedTimeTo
  */
  @Min(0L) 
  @Schema(name = "cachedTimeTo", description = "UNIX timestamp (UTC) of the interval end", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("cachedTimeTo")
  public Long getCachedTimeTo() {
    return cachedTimeTo;
  }

  public void setCachedTimeTo(Long cachedTimeTo) {
    this.cachedTimeTo = cachedTimeTo;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CachedTimeIntervalDto cachedTimeInterval = (CachedTimeIntervalDto) o;
    return Objects.equals(this.cachedTimeFrom, cachedTimeInterval.cachedTimeFrom) &&
        Objects.equals(this.cachedTimeTo, cachedTimeInterval.cachedTimeTo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(cachedTimeFrom, cachedTimeTo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CachedTimeIntervalDto {\n");
    sb.append("    cachedTimeFrom: ").append(toIndentedString(cachedTimeFrom)).append("\n");
    sb.append("    cachedTimeTo: ").append(toIndentedString(cachedTimeTo)).append("\n");
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

