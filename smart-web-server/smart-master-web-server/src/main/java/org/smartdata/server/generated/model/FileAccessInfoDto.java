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
 * FileAccessInfoDto
 */

@JsonTypeName("FileAccessInfo")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class FileAccessInfoDto {

  private Long id;

  private String path;

  private Integer accessCount;

  private Long lastAccessTime;

  public FileAccessInfoDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public FileAccessInfoDto(Long id, String path, Integer accessCount, Long lastAccessTime) {
    this.id = id;
    this.path = path;
    this.accessCount = accessCount;
    this.lastAccessTime = lastAccessTime;
  }

  public FileAccessInfoDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Id of the file
   * @return id
   */
  @NotNull
  @Schema(name = "id", description = "Id of the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public FileAccessInfoDto path(String path) {
    this.path = path;
    return this;
  }

  /**
   * Path of the file
   * @return path
   */
  @NotNull
  @Schema(name = "path", description = "Path of the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public FileAccessInfoDto accessCount(Integer accessCount) {
    this.accessCount = accessCount;
    return this;
  }

  /**
   * Number of accesses to the file
   * @return accessCount
   */
  @NotNull
  @Schema(name = "accessCount", description = "Number of accesses to the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("accessCount")
  public Integer getAccessCount() {
    return accessCount;
  }

  public void setAccessCount(Integer accessCount) {
    this.accessCount = accessCount;
  }

  public FileAccessInfoDto lastAccessTime(Long lastAccessTime) {
    this.lastAccessTime = lastAccessTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the last file access
   * @return lastAccessTime
   */
  @NotNull
  @Schema(name = "lastAccessTime", description = "UNIX timestamp (UTC) of the last file access", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("lastAccessTime")
  public Long getLastAccessTime() {
    return lastAccessTime;
  }

  public void setLastAccessTime(Long lastAccessTime) {
    this.lastAccessTime = lastAccessTime;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FileAccessInfoDto fileAccessInfo = (FileAccessInfoDto) o;
    return Objects.equals(this.id, fileAccessInfo.id) &&
        Objects.equals(this.path, fileAccessInfo.path) &&
        Objects.equals(this.accessCount, fileAccessInfo.accessCount) &&
        Objects.equals(this.lastAccessTime, fileAccessInfo.lastAccessTime);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, path, accessCount, lastAccessTime);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class FileAccessInfoDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    path: ").append(toIndentedString(path)).append("\n");
    sb.append("    accessCount: ").append(toIndentedString(accessCount)).append("\n");
    sb.append("    lastAccessTime: ").append(toIndentedString(lastAccessTime)).append("\n");
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

