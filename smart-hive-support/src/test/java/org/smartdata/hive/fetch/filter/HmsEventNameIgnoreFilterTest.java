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
package org.smartdata.hive.fetch.filter;

import org.apache.hadoop.conf.Configuration;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.smartdata.hive.HiveSmartConf;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.HiveSmartConf.HMS_EVENT_IGNORE_PATTERNS;
import static org.smartdata.hive.fetch.filter.HmsEventNameFilterBaseTest.Parameters.patterns;

public class HmsEventNameIgnoreFilterTest extends HmsEventNameFilterBaseTest {
  @Parameterized.Parameters(
      name = "patterns = {0}, inputString = {1}, expectedResult = {2}")
  public static Object[] parameters() {
    return new Object[][]{
        patterns("ignore.*").shouldIgnore("ignore"),
        patterns("ignore.*").shouldIgnore("ignore.tb1"),
        patterns("ignore.*").shouldIgnore("ignored.tb1"),
        patterns("ignore.*").shouldIgnore("ignore.ignore"),
        patterns("ignore.*").shouldAccept("ignor"),
        patterns("ignore.*").shouldAccept("ignor.tb"),
        patterns("ignore.*").shouldAccept("another_db"),

        patterns(".*ignore.*").shouldIgnore("db.ignore"),
        patterns(".*ignore.*").shouldIgnore("db.ignored"),
        patterns(".*ignore.*").shouldIgnore("ignore"),
        patterns(".*ignore.*").shouldIgnore("ignore.tb1"),
        patterns(".*ignore.*").shouldIgnore("db.tb.ignored_partition"),
        patterns(".*ignore.*").shouldAccept("ignor.tb"),
        patterns(".*ignore.*").shouldAccept("another_db.ignor"),
        patterns(".*ignore.*").shouldAccept("another_db"),
        patterns(".*ignore.*").shouldAccept("another_db.ignor"),

        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("db1.tbl1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("db2"),
        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("other.db2.t1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("db3"),
        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("db3.t1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("db1"),
    };
  }

  @Test
  public void testBuildFilterFromConfig() {
    Configuration configuration = new Configuration();
    configuration.set(HMS_EVENT_IGNORE_PATTERNS, ".*ignore.*,db1.*");
    Optional<HmsEventFilter> hmsEventFilter = HmsEventNameIgnoreFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(hmsEventFilter.isPresent());
  }

  @Test
  public void testNoOpFilterFromConfig() {
    Configuration configuration = new Configuration();
    Optional<HmsEventFilter> hmsEventFilter = HmsEventNameIgnoreFilter.fromConf(
        new HiveSmartConf(configuration));

    assertFalse(hmsEventFilter.isPresent());
  }

  @Override
  protected HmsEventFilter buildFilter(List<String> patterns) {
    return new HmsEventNameIgnoreFilter(patterns);
  }
}