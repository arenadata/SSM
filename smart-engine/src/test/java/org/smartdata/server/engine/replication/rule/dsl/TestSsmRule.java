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
package org.smartdata.server.engine.replication.rule.dsl;

import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.smartdata.server.engine.replication.rule.dsl.MatchesCondition.nameMatches;
import static org.smartdata.server.engine.replication.rule.dsl.MatchesCondition.pathMatches;

public class TestSsmRule {
  private static final Instant START = timePoint("2026-10-21T10:00:00");
  private static final Instant END = timePoint("2026-10-22T10:00:00");

  @Test
  public void testRenderTriggers() {
    assertEquals("every 300s",
        new EveryTrigger(Duration.ofMinutes(5), null, null).render());
    assertEquals("every 300s from \"2026-10-21 10:00:00\"",
        new EveryTrigger(Duration.ofMinutes(5), START, null).render());
    assertEquals("every 300s from \"2026-10-21 10:00:00\" to \"2026-10-22 10:00:00\"",
        new EveryTrigger(Duration.ofMinutes(5), START, END).render());
    assertEquals("every 300s from now to \"2026-10-22 10:00:00\"",
        new EveryTrigger(Duration.ofMinutes(5), null, END).render());
    assertEquals("at \"2026-10-21 10:00:00\"", new AtTrigger(START).render());
    assertEquals("at now", new AtTrigger(null).render());
  }

  @Test
  public void testRenderConditions() {
    assertEquals("path matches \"/data/*\"", pathMatches("/data/*").render());
    assertEquals("name matches \"db1.a\" or (name matches \"db1.b\" or name matches \"db1.c\")",
        new OrCondition(List.of(
            nameMatches("db1.a"),
            new OrCondition(List.of(nameMatches("db1.b"), nameMatches("db1.c")))))
            .render());
    assertThrows(IllegalArgumentException.class, () -> pathMatches("/data/\"quoted\"/*"));
  }

  @Test
  public void testRenderAction() {
    assertEquals("hms-sync -dest thrift://backup:9083 -cascade -nameservice_rename \"ns1 ns2\"",
        RuleAction.action("hms-sync")
            .arg("-dest", "thrift://backup:9083")
            .flag("-cascade")
            .arg("-nameservice_rename", "ns1 ns2")
            .render());
  }

  @Test
  public void testRenderRule() {
    SsmRule.Builder rule = SsmRule.builder()
        .objectType(RuleObjectType.FILE)
        .condition(pathMatches("/data/*"))
        .action(RuleAction.action("sync").arg("-dest", "hdfs://ns2/data/"));

    assertEquals("file: path matches \"/data/*\" | sync -dest hdfs://ns2/data/",
        rule.build().render());
    assertEquals("file: at now | path matches \"/data/*\" | sync -dest hdfs://ns2/data/",
        rule.trigger(new AtTrigger(null)).build().render());
  }

  private static Instant timePoint(String dateTime) {
    return LocalDateTime.parse(dateTime).atZone(ZoneId.systemDefault()).toInstant();
  }
}
