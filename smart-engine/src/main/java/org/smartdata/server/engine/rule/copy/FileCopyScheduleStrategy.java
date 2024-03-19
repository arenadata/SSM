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

import org.smartdata.utils.StringUtil;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.smartdata.server.engine.rule.copy.DiffCreationTimeCopyScheduleStrategy.DiffSelectionStrategy.EARLIEST;
import static org.smartdata.server.engine.rule.copy.DiffCreationTimeCopyScheduleStrategy.DiffSelectionStrategy.LATEST;

public interface FileCopyScheduleStrategy {
  enum Strategy {
    UNORDERED,
    FIFO,
    LIFO
  }

  String wrapGetFilesToCopyQuery(String query, List<String> pathTemplates);

  static FileCopyScheduleStrategy of(String rawStrategyName) {
    try {
      Strategy strategy = Strategy.valueOf(rawStrategyName.toUpperCase());
      return of(strategy);
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException(
          "Wrong file copy schedule strategy "
              + rawStrategyName + ". Should be one of: "
              + Arrays.toString(Strategy.values()));
    }
  }

  static FileCopyScheduleStrategy of(Strategy strategyName) {
      switch (strategyName) {
        case FIFO:
          return new DiffCreationTimeCopyScheduleStrategy(EARLIEST);
        case LIFO:
          return new DiffCreationTimeCopyScheduleStrategy(LATEST);
        default:
          return new OrderAgnosticCopyScheduleStrategy();
      }
  }

  static String pathTemplatesToSqlCondition(List<String> pathTemplates) {
    return pathTemplates.stream()
        .map(StringUtil::ssmPatternToSqlLike)
        .map(template -> "src LIKE '" + template + "'")
        .collect(Collectors.joining(" OR "));
  }
}
