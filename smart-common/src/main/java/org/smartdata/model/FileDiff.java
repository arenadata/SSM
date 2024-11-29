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
package org.smartdata.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
@AllArgsConstructor
@Builder(toBuilder = true)
public class FileDiff {
  private long diffId;
  private long ruleId;
  private FileDiffType diffType;
  private String src;
  private Map<String, String> parameters;
  private FileDiffState state;
  private long createTime;

  public FileDiff() {
    this.createTime = System.currentTimeMillis();
    this.parameters = new HashMap<>();
  }

  public FileDiff(FileDiffType diffType) {
    this();
    this.diffType = diffType;
    this.state = FileDiffState.PENDING;
  }

  public FileDiff(FileDiffType diffType, FileDiffState state) {
    this();
    this.diffType = diffType;
    this.state = state;
  }

  public void setParameter(String key, String value) {
    parameters.put(key, value);
  }
}
