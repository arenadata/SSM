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

import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.smartdata.cmdlet.parser.CmdletParserContext.State.ESCAPED_CHAR;
import static org.smartdata.cmdlet.parser.CmdletParserContext.State.INSIDE_STR_LITERAL;
import static org.smartdata.cmdlet.parser.CmdletParserContext.State.INSIDE_TOKEN;

public class CmdletParser {
  private static final String REG_ACTION_NAME = "^[a-zA-Z]+[a-zA-Z0-9_]*";

  public ParsedCmdlet parse(String cmdlet) throws ParseException {
    if (StringUtils.isBlank(cmdlet)) {
      return null;
    }

    char[] chars = (cmdlet + " ").toCharArray();

    CmdletParserContext context = new CmdletParserContext(cmdlet);
    for (int idx = 0; idx < chars.length; ++idx) {
      context.setParseIndex(idx);

      switch (chars[idx]) {
        case ' ':
        case '\t':
          onWhitespace(context, chars[idx]);
          break;
        case ';':
          onActionDelimiter(context);
          break;
        case '"':
          onQuote(context);
          break;
        case '\n':
        case '\r':
          onNewLine(context);
          break;
        case '\\':
          // handle case of escaped '\'
          if (!context.isInState(ESCAPED_CHAR)) {
            context.inAdditionalState(ESCAPED_CHAR);
            break;
          }
        default:
          onTokenChar(context, chars[idx]);
      }
    }

    if (context.isInState(INSIDE_STR_LITERAL)) {
      throw new ParseException("Unexpected break of string literal", chars.length);
    }

    if (!context.getCurrentTokens().isEmpty()) {
      parseAction(context);
    }

    return context.buildParsedCmdlet();
  }

  private void onWhitespace(CmdletParserContext context, char currentChar) {
    if (context.isInState(INSIDE_STR_LITERAL)) {
      context.addChar(currentChar);
    } else if (context.isInState(INSIDE_TOKEN)) {
      context.tokenEnded();
    }
  }

  private void onTokenChar(CmdletParserContext context, char currentChar) {
    if (!context.isInState(INSIDE_STR_LITERAL)) {
      context.stateTransition(INSIDE_TOKEN);
    }
    context.addChar(currentChar);
  }

  private void onActionDelimiter(CmdletParserContext context) throws ParseException {
    if (context.isInState(INSIDE_STR_LITERAL)) {
      throw new ParseException("Unexpected break of string literal", context.getParseIndex());
    } else if (context.isInState(INSIDE_TOKEN)) {
      context.tokenEnded();
    }
    parseAction(context);
  }

  private void onQuote(CmdletParserContext context) throws ParseException {
    if (context.isInState(INSIDE_TOKEN)) {
      throw new ParseException("Unexpected \"", context.getParseIndex());
    } else if (context.isInState(INSIDE_STR_LITERAL)) {
      context.tokenEnded();
    } else {
      context.stateTransition(INSIDE_STR_LITERAL);
    }
  }

  private void onNewLine(CmdletParserContext context) throws ParseException {
    if (context.isInState(INSIDE_TOKEN)) {
      context.tokenEnded();
    } else if (context.isInState(INSIDE_STR_LITERAL)) {
      throw new ParseException("Multiline string literals not supported", context.getParseIndex());
    }
  }

  private void parseAction(CmdletParserContext context) throws ParseException {
    List<String> tokens = context.getCurrentTokens();
    if (tokens.isEmpty()) {
      throw new ParseException("Cmdlet should have at least one action",
          context.getParseIndex());
    }

    String actionName = tokens.get(0);
    if (!actionName.matches(REG_ACTION_NAME)) {
      throw new ParseException("Invalid action name: " + actionName, context.getParseIndex());
    }

    List<String> actionArgs = tokens.subList(1, tokens.size());
    context.addAction(actionName, toArgMap(actionArgs));
    context.clearTokens();
  }

  public static Map<String, String> toArgMap(List<String> args)
      throws ParseException {
    Map<String, String> argsMap = new HashMap<>();

    String lastOptionKey = null;
    for (String arg : args) {
      if (arg.startsWith("-")) {
        argsMap.put(arg, "");
        lastOptionKey = arg;
        continue;
      }
      if (lastOptionKey == null) {
        throw new ParseException(
            "Invalid action option format: '" + arg + "'", 0);
      }
      argsMap.put(lastOptionKey, arg);
      lastOptionKey = null;
    }
    return argsMap;
  }
}
