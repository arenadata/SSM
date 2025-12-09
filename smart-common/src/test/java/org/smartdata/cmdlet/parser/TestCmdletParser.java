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
package org.smartdata.cmdlet.parser;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;

import java.text.ParseException;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class TestCmdletParser {
  private final CmdletParser cmdletParser = new CmdletParser();

  @Test
  public void testHandleEmptyCmdletString() throws ParseException {
    ParsedCmdlet parsedCmdlet = cmdletParser.parse(null);
    assertNull(parsedCmdlet);

    parsedCmdlet = cmdletParser.parse("");
    assertNull(parsedCmdlet);

    parsedCmdlet = cmdletParser.parse(" \t\n");
    assertNull(parsedCmdlet);
  }

  @Test
  public void testParseSingleAction() throws ParseException {
    Map<String, String> actionArgs = ImmutableMap.of(
        "-key1", "value1",
        "-key2", "value2",
        "-key3", "/val3",
        "-key4", ""
    );

    ParsedCmdlet expectedCmdlet = ParsedCmdlet.newBuilder()
        .setCmdletString("action -key1 value1 -key2 \"value2\" -key3 \\/val3 -key4")
        .addAction("action", actionArgs)
        .build();
    testParseAction(expectedCmdlet);
  }

  @Test
  public void testParseMultipleActions() throws ParseException {
    Map<String, String> firstActionArgs = ImmutableMap.of(
        "-key1", "value1",
        "-key2", ""
    );

    Map<String, String> secondActionArgs = ImmutableMap.of(
        "-option", "withVal",
        "-option2", "\\2",
        "-withoutVal", ""
    );

    ParsedCmdlet expectedCmdlet = ParsedCmdlet.newBuilder()
        .setCmdletString("action1 -key1 \"value1\" -key2; "
            + "action2 -option withVal -option2 \\\\2 -withoutVal")
        .addAction("action1", firstActionArgs)
        .addAction("action2", secondActionArgs)
        .build();
    testParseAction(expectedCmdlet);
  }

  @Test
  public void testHandleWhitespaces() throws ParseException {
    Map<String, String> actionArgs = ImmutableMap.of(
        "-key1", "val1",
        "-key2", "\tval 2",
        "-key3", ""
    );

    ParsedCmdlet expectedCmdlet = ParsedCmdlet.newBuilder()
        .setCmdletString("action -key1     val1\t-key2\n \"\tval 2\" \r\n-key3")
        .addAction("action", actionArgs)
        .build();
    testParseAction(expectedCmdlet);
  }

  @Test
  public void testThrowOnUnfinishedStringLiteral() {
    testThrowParseException(
        "buggy_action -key 1 -key2 \"str_literal",
        "Unexpected break of string literal"
    );
  }

  @Test
  public void testThrowOnUnfinishedStringLiteralBeforeDelimiter() {
    testThrowParseException(
        "buggyAction -key2 \"str_literal; anotherAction -key val",
        "Unexpected break of string literal"
    );
  }

  @Test
  public void testThrowOnQuoteInsideToken() {
    testThrowParseException(
        "action -key1 str_\"literal",
        "Unexpected \""
    );
  }

  @Test
  public void testThrowOnMultilineStringLiterals() {
    testThrowParseException(
        "action_1 -key1 \"str\nliteral\"",
        "Multiline string literals not supported"
    );
  }

  @Test
  public void testThrowOnInvalidActionArgFormat() {
    testThrowParseException(
        "action val1",
        "Invalid action option format: 'val1'"
    );

    testThrowParseException(
        "action -key val1 val2",
        "Invalid action option format: 'val2'"
    );
  }

  @Test
  public void testThrowOnInvalidActionName() {
    Lists.newArrayList(
        "1",
        "1action",
        "_action",
        "another_symbol!",
        "another_s@mb0l"
    ).forEach(this::testThrowOnInvalidActionName);
  }

  private void testThrowOnInvalidActionName(String actionName) {
    testThrowParseException(actionName, "Invalid action name: " + actionName);
  }

  private void testThrowParseException(String action, String message) {
    ParseException parseException = Assert.assertThrows(
        ParseException.class,
        () -> cmdletParser.parse(action));

    assertEquals(message, parseException.getMessage());
  }

  private void testParseAction(ParsedCmdlet expectedCmdlet) throws ParseException {
    ParsedCmdlet parsedCmdlet = cmdletParser.parse(expectedCmdlet.getCmdletString());
    assertEquals(expectedCmdlet, parsedCmdlet);
  }
}
