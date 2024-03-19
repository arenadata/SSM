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

package org.smartdata.server.engine.rule.copy;

import java.util.List;

public class DiffCreationTimeCopyScheduleStrategy implements FileCopyScheduleStrategy {
  public DiffCreationTimeCopyScheduleStrategy(DiffSelectionStrategy diffSelectionStrategy) {
    this.diffSelectionStrategy = diffSelectionStrategy;
  }

  /** Behaviour in case if there are several pending diff for the same file. */
  public enum DiffSelectionStrategy {
    /** Select pending diff with the earliest creation time. */
    EARLIEST,
    /** Select pending diff with the latest creation time. */
    LATEST
  }

  private final DiffSelectionStrategy diffSelectionStrategy;

  @Override
  public String wrapGetFilesToCopyQuery(String query, List<String> pathTemplates) {
    return "SELECT file_diff.src "
        + "FROM file_diff "
        + "LEFT JOIN (" + query + ") as q "
        + "ON file_diff.src = q.path "
        // select diffs of files from query
        + "WHERE q.path IS NOT NULL OR "
        // or pending diffs of files that were renamed/removed from HDFS
        // and now are only available in the file diffs table
        + "(state = 0 AND diff_type IN (1,2) AND ("
        + FileCopyScheduleStrategy.pathTemplatesToSqlCondition(pathTemplates)
        + ")) "
        // choose only one pending file_diff per file based on the provided strategy
        + "GROUP BY file_diff.src "
        + "ORDER BY " + orderClause() + ";";
  }

  private String orderClause() {
    return diffSelectionStrategy == DiffSelectionStrategy.EARLIEST
        ? "MIN(create_time)"
        : "MAX(create_time) DESC";
  }
}
