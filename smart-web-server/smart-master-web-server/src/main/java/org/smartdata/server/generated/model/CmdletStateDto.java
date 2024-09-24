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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import javax.annotation.Generated;

/**
 * Current state of the cmdlet
 */

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public enum CmdletStateDto {
  
  NOT_INITED("NOT_INITED"),
  
  PENDING("PENDING"),
  
  SCHEDULED("SCHEDULED"),
  
  DISPATCHED("DISPATCHED"),
  
  EXECUTING("EXECUTING"),
  
  CANCELLED("CANCELLED"),
  
  DISABLED("DISABLED"),
  
  FAILED("FAILED"),
  
  DONE("DONE");

  private String value;

  CmdletStateDto(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return String.valueOf(value);
  }

  @JsonCreator
  public static CmdletStateDto fromValue(String value) {
    for (CmdletStateDto b : CmdletStateDto.values()) {
      if (b.value.equals(value)) {
        return b;
      }
    }
    throw new IllegalArgumentException("Unexpected value '" + value + "'");
  }
}

