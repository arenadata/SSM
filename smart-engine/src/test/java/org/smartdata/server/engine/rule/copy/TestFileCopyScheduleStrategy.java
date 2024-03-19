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

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class TestFileCopyScheduleStrategy {
  @Test
  public void checkOrderAgnosticCopyScheduleStrategy() {
    FileCopyScheduleStrategy orderAgnosticStrategy =
        FileCopyScheduleStrategy.of("UNORDERED");

    String wrappedQuery = orderAgnosticStrategy.wrapGetFilesToCopyQuery(
        "select * from test",
        Arrays.asList("/path1/*", "/path2/*"));

    String expectedQuery = "select * from test "
        + "UNION SELECT src FROM file_diff "
        + "WHERE state = 0 AND diff_type IN (1,2) AND ("
        + "src LIKE '/path1/%' OR src LIKE '/path2/%'"
        + ");";

    Assert.assertEquals(expectedQuery, wrappedQuery);
  }

  @Test
  public void checkFifoCopyScheduleStrategy() {
    FileCopyScheduleStrategy orderAgnosticStrategy =
        FileCopyScheduleStrategy.of("FIFO");

    String wrappedQuery = orderAgnosticStrategy.wrapGetFilesToCopyQuery(
        "select * from test",
        Arrays.asList("/path1/*", "/path2/*"));

    String expectedQuery = "SELECT file_diff.src "
        + "FROM file_diff "
        + "LEFT JOIN (select * from test) as q "
        + "ON file_diff.src = q.path "
        + "WHERE q.path IS NOT NULL OR "
        + "(state = 0 AND diff_type IN (1,2) AND ("
        + "src LIKE '/path1/%' OR src LIKE '/path2/%'"
        + ")) GROUP BY file_diff.src "
        + "ORDER BY MIN(create_time);";

    Assert.assertEquals(expectedQuery, wrappedQuery);
  }

  @Test
  public void checkLifoCopyScheduleStrategy() {
    FileCopyScheduleStrategy orderAgnosticStrategy =
        FileCopyScheduleStrategy.of("LIFO");

    String wrappedQuery = orderAgnosticStrategy.wrapGetFilesToCopyQuery(
        "select * from test",
        Arrays.asList("/path1/*", "/path2/*"));

    String expectedQuery = "SELECT file_diff.src "
        + "FROM file_diff "
        + "LEFT JOIN (select * from test) as q "
        + "ON file_diff.src = q.path "
        + "WHERE q.path IS NOT NULL OR "
        + "(state = 0 AND diff_type IN (1,2) AND ("
        + "src LIKE '/path1/%' OR src LIKE '/path2/%'"
        + ")) GROUP BY file_diff.src "
        + "ORDER BY MAX(create_time) DESC;";

    Assert.assertEquals(expectedQuery, wrappedQuery);
  }

  @Test
  public void checkThrowIfWrongStrategyName() {
    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class,
        () -> FileCopyScheduleStrategy.of("unknown"));

    Assert.assertTrue(exception.getMessage()
        .contains("Wrong file copy schedule strategy"));
  }
}
