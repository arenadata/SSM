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
 * ClusterNodeDto
 */

@JsonTypeName("ClusterNode")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class ClusterNodeDto {

  private String id;

  private String host;

  private Integer port;

  private ExecutorTypeDto executorType;

  private Long registrationTime;

  private Integer executorsCount;

  private Long cmdletsExecuted;

  public ClusterNodeDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public ClusterNodeDto(String id, String host, Integer port, ExecutorTypeDto executorType, Long registrationTime, Integer executorsCount, Long cmdletsExecuted) {
    this.id = id;
    this.host = host;
    this.port = port;
    this.executorType = executorType;
    this.registrationTime = registrationTime;
    this.executorsCount = executorsCount;
    this.cmdletsExecuted = cmdletsExecuted;
  }

  public ClusterNodeDto id(String id) {
    this.id = id;
    return this;
  }

  /**
   * id of the node
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "id of the node", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public ClusterNodeDto host(String host) {
    this.host = host;
    return this;
  }

  /**
   * host on which the node is running
   * @return host
  */
  @NotNull 
  @Schema(name = "host", description = "host on which the node is running", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("host")
  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public ClusterNodeDto port(Integer port) {
    this.port = port;
    return this;
  }

  /**
   * port to which the node is bound
   * @return port
  */
  @NotNull 
  @Schema(name = "port", description = "port to which the node is bound", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("port")
  public Integer getPort() {
    return port;
  }

  public void setPort(Integer port) {
    this.port = port;
  }

  public ClusterNodeDto executorType(ExecutorTypeDto executorType) {
    this.executorType = executorType;
    return this;
  }

  /**
   * Get executorType
   * @return executorType
  */
  @NotNull @Valid 
  @Schema(name = "executorType", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("executorType")
  public ExecutorTypeDto getExecutorType() {
    return executorType;
  }

  public void setExecutorType(ExecutorTypeDto executorType) {
    this.executorType = executorType;
  }

  public ClusterNodeDto registrationTime(Long registrationTime) {
    this.registrationTime = registrationTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the node registration in master
   * @return registrationTime
  */
  @NotNull 
  @Schema(name = "registrationTime", description = "UNIX timestamp (UTC) of the node registration in master", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("registrationTime")
  public Long getRegistrationTime() {
    return registrationTime;
  }

  public void setRegistrationTime(Long registrationTime) {
    this.registrationTime = registrationTime;
  }

  public ClusterNodeDto executorsCount(Integer executorsCount) {
    this.executorsCount = executorsCount;
    return this;
  }

  /**
   * Number of cmdlet executors
   * @return executorsCount
  */
  @NotNull 
  @Schema(name = "executorsCount", description = "Number of cmdlet executors", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("executorsCount")
  public Integer getExecutorsCount() {
    return executorsCount;
  }

  public void setExecutorsCount(Integer executorsCount) {
    this.executorsCount = executorsCount;
  }

  public ClusterNodeDto cmdletsExecuted(Long cmdletsExecuted) {
    this.cmdletsExecuted = cmdletsExecuted;
    return this;
  }

  /**
   * Number of executed cmdlets on this node
   * @return cmdletsExecuted
  */
  @NotNull 
  @Schema(name = "cmdletsExecuted", description = "Number of executed cmdlets on this node", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("cmdletsExecuted")
  public Long getCmdletsExecuted() {
    return cmdletsExecuted;
  }

  public void setCmdletsExecuted(Long cmdletsExecuted) {
    this.cmdletsExecuted = cmdletsExecuted;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClusterNodeDto clusterNode = (ClusterNodeDto) o;
    return Objects.equals(this.id, clusterNode.id) &&
        Objects.equals(this.host, clusterNode.host) &&
        Objects.equals(this.port, clusterNode.port) &&
        Objects.equals(this.executorType, clusterNode.executorType) &&
        Objects.equals(this.registrationTime, clusterNode.registrationTime) &&
        Objects.equals(this.executorsCount, clusterNode.executorsCount) &&
        Objects.equals(this.cmdletsExecuted, clusterNode.cmdletsExecuted);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, host, port, executorType, registrationTime, executorsCount, cmdletsExecuted);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClusterNodeDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    host: ").append(toIndentedString(host)).append("\n");
    sb.append("    port: ").append(toIndentedString(port)).append("\n");
    sb.append("    executorType: ").append(toIndentedString(executorType)).append("\n");
    sb.append("    registrationTime: ").append(toIndentedString(registrationTime)).append("\n");
    sb.append("    executorsCount: ").append(toIndentedString(executorsCount)).append("\n");
    sb.append("    cmdletsExecuted: ").append(toIndentedString(cmdletsExecuted)).append("\n");
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

