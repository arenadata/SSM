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
 * ActionMetadataDto
 */

@JsonTypeName("ActionMetadata")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class ActionMetadataDto {

  private String name;

  private String usage = null;

  public ActionMetadataDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public ActionMetadataDto(String name) {
    this.name = name;
  }

  public ActionMetadataDto name(String name) {
    this.name = name;
    return this;
  }

  /**
   * SSM host on which this action is running
   * @return name
   */
  @NotNull
  @Schema(name = "name", description = "SSM host on which this action is running", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("name")
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public ActionMetadataDto usage(String usage) {
    this.usage = usage;
    return this;
  }

  /**
   * SSM host on which this action is running
   * @return usage
   */

  @Schema(name = "usage", description = "SSM host on which this action is running", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("usage")
  public String getUsage() {
    return usage;
  }

  public void setUsage(String usage) {
    this.usage = usage;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ActionMetadataDto actionMetadata = (ActionMetadataDto) o;
    return Objects.equals(this.name, actionMetadata.name) &&
        Objects.equals(this.usage, actionMetadata.usage);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, usage);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ActionMetadataDto {\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    usage: ").append(toIndentedString(usage)).append("\n");
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

