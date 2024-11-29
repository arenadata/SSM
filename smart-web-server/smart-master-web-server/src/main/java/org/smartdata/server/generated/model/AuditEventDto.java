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
 * AuditEventDto
 */

@JsonTypeName("AuditEvent")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class AuditEventDto {

  private Long id;

  private String username;

  private Long timestamp;

  private AuditObjectTypeDto objectType;

  private Long objectId;

  private AuditOperationDto operation;

  private AuditEventResultDto result;

  public AuditEventDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public AuditEventDto(Long id, String username, Long timestamp, AuditObjectTypeDto objectType, Long objectId, AuditOperationDto operation, AuditEventResultDto result) {
    this.id = id;
    this.username = username;
    this.timestamp = timestamp;
    this.objectType = objectType;
    this.objectId = objectId;
    this.operation = operation;
    this.result = result;
  }

  public AuditEventDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Event id
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "Event id", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public AuditEventDto username(String username) {
    this.username = username;
    return this;
  }

  /**
   * Name of the user that perform the action
   * @return username
  */
  @NotNull 
  @Schema(name = "username", description = "Name of the user that perform the action", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("username")
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public AuditEventDto timestamp(Long timestamp) {
    this.timestamp = timestamp;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the event
   * @return timestamp
  */
  @NotNull 
  @Schema(name = "timestamp", description = "UNIX timestamp (UTC) of the event", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("timestamp")
  public Long getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(Long timestamp) {
    this.timestamp = timestamp;
  }

  public AuditEventDto objectType(AuditObjectTypeDto objectType) {
    this.objectType = objectType;
    return this;
  }

  /**
   * Get objectType
   * @return objectType
  */
  @NotNull @Valid 
  @Schema(name = "objectType", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("objectType")
  public AuditObjectTypeDto getObjectType() {
    return objectType;
  }

  public void setObjectType(AuditObjectTypeDto objectType) {
    this.objectType = objectType;
  }

  public AuditEventDto objectId(Long objectId) {
    this.objectId = objectId;
    return this;
  }

  /**
   * Id of the corresponding object (rule or cmdlet)
   * @return objectId
  */
  @NotNull 
  @Schema(name = "objectId", description = "Id of the corresponding object (rule or cmdlet)", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("objectId")
  public Long getObjectId() {
    return objectId;
  }

  public void setObjectId(Long objectId) {
    this.objectId = objectId;
  }

  public AuditEventDto operation(AuditOperationDto operation) {
    this.operation = operation;
    return this;
  }

  /**
   * Get operation
   * @return operation
  */
  @NotNull @Valid 
  @Schema(name = "operation", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("operation")
  public AuditOperationDto getOperation() {
    return operation;
  }

  public void setOperation(AuditOperationDto operation) {
    this.operation = operation;
  }

  public AuditEventDto result(AuditEventResultDto result) {
    this.result = result;
    return this;
  }

  /**
   * Get result
   * @return result
  */
  @NotNull @Valid 
  @Schema(name = "result", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("result")
  public AuditEventResultDto getResult() {
    return result;
  }

  public void setResult(AuditEventResultDto result) {
    this.result = result;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuditEventDto auditEvent = (AuditEventDto) o;
    return Objects.equals(this.id, auditEvent.id) &&
        Objects.equals(this.username, auditEvent.username) &&
        Objects.equals(this.timestamp, auditEvent.timestamp) &&
        Objects.equals(this.objectType, auditEvent.objectType) &&
        Objects.equals(this.objectId, auditEvent.objectId) &&
        Objects.equals(this.operation, auditEvent.operation) &&
        Objects.equals(this.result, auditEvent.result);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, username, timestamp, objectType, objectId, operation, result);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuditEventDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("    timestamp: ").append(toIndentedString(timestamp)).append("\n");
    sb.append("    objectType: ").append(toIndentedString(objectType)).append("\n");
    sb.append("    objectId: ").append(toIndentedString(objectId)).append("\n");
    sb.append("    operation: ").append(toIndentedString(operation)).append("\n");
    sb.append("    result: ").append(toIndentedString(result)).append("\n");
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

