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
package org.smartdata.utils;

import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

public class FormattingUtil {
  public static String actionToString(String action, Map<String, String> args) {
    StringJoiner actionBuilder = new StringJoiner(" ");
    actionBuilder.add(action);

    if (args != null) {
      args.forEach((key, value) ->
          actionBuilder.add(formatArg(key)).add(formatArg(value)));
    }

    return actionBuilder.toString().trim();
  }

  private static String formatArg(String arg) {
    return Optional.ofNullable(arg)
            .map(FormattingUtil::formatArgInternal)
            .orElse("");
  }

  private static String formatArgInternal(String arg) {
    String formattedArg = arg.replace("\\", "\\\\")
            .replace("\"", "\\\"");
    return formattedArg.matches(".*\\s.*")
            ? "\"" + formattedArg + "\""
            : formattedArg;
  }
}
