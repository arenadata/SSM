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
package org.smartdata.test.util;

import lombok.experimental.UtilityClass;

import java.io.BufferedReader;
import java.io.StringReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@UtilityClass
public class LogsUtil {
  private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})");
  private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  public static List<String> getLinesContainsText(String logs, String containsText) {
    return new BufferedReader(new StringReader(logs))
        .lines()
        .filter(line -> line.contains(containsText))
        .collect(Collectors.toList());
  }

  public static List<LocalDateTime> getTimeFromLines(List<String> lines) {
    return lines.stream()
        .map(LogsUtil::extractTime)
        .collect(Collectors.toList());
  }

  private static LocalDateTime extractTime(String logLine) {
    Matcher matcher = TIMESTAMP_PATTERN.matcher(logLine);
    if (matcher.find()) {
      return LocalDateTime.parse(matcher.group(1), FORMATTER);
    }
    throw new IllegalArgumentException("No timestamp found in: " + logLine);
  }
}
