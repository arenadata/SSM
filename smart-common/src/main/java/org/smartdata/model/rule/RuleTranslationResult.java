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
package org.smartdata.model.rule;

import org.smartdata.model.CmdletDescriptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Result of rule translation. A guide for execution.
 */
public class RuleTranslationResult {
  private final int retSqlIndex;
  private final List<String> sqlStatements;
  private final Map<String, List<Object>> dynamicParameters;
  private final TimeBasedScheduleInfo scheduleInfo;
  private final CmdletDescriptor cmdDescriptor;
  private final int[] condPosition;
  private List<String> pathPatterns;

  public RuleTranslationResult(List<String> sqlStatements,
                               Map<String,
                               List<Object>> dynamicParameters,
                               int retSqlIndex,
                               TimeBasedScheduleInfo scheduleInfo,
                               CmdletDescriptor cmdDescriptor,
                               int[] condPosition,
                               List<String> pathPatterns) {
    this.sqlStatements = sqlStatements;
    this.dynamicParameters = dynamicParameters;
    this.retSqlIndex = retSqlIndex;
    this.scheduleInfo = scheduleInfo;
    this.cmdDescriptor = cmdDescriptor;
    this.condPosition = condPosition;
    this.pathPatterns = pathPatterns;
  }

  public CmdletDescriptor getCmdDescriptor() {
    return cmdDescriptor;
  }

  public List<String> getSqlStatements() {
    return sqlStatements;
  }

  public List<Object> getParameter(String paramName) {
    return dynamicParameters.get(paramName);
  }

  public int getRetSqlIndex() {
    return retSqlIndex;
  }

  public TimeBasedScheduleInfo getScheduleInfo() {
    return scheduleInfo;
  }

  public int[] getCondPosition() {
    return condPosition;
  }

  public List<String> getPathPatterns() {
    return pathPatterns;
  }

  public void setPathPatterns(List<String> pathPatterns) {
    this.pathPatterns = pathPatterns;
  }

  public RuleTranslationResult copy() {
    return new RuleTranslationResult(
        new ArrayList<>(sqlStatements),
        dynamicParameters,
        retSqlIndex,
        scheduleInfo,
        cmdDescriptor,
        condPosition,
        new ArrayList<>(pathPatterns)
    );
  }
}
