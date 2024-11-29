/*
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

import type { Recognizer } from 'antlr4';
import { CharStream, ErrorListener } from 'antlr4';
import SmartRuleLexer from './SmartRuleLexer';
import { SmartRuleToken } from './smartRuleTokensProvider.types';

const EOF = -1;

export const getTokens = (input: string): SmartRuleToken[] => {
  const errorStartingPoints: number[] = [];

  class ErrorCollectorListener<Token> extends ErrorListener<Token> {
    syntaxError(
      recognizer: Recognizer<Token>,
      offendingSymbol: Token,
      line: number,
      column: number,
      // msg: string,
      // e: RecognitionException | undefined,
    ) {
      errorStartingPoints.push(column);
    }
  }

  const chars = new CharStream(input);
  const lexer = new SmartRuleLexer(chars);

  lexer.removeErrorListeners();
  const errorListener = new ErrorCollectorListener();
  lexer.addErrorListener(errorListener);

  const result: SmartRuleToken[] = [];

  let done = false;
  do {
    const token = lexer.nextToken();
    if (token == null) {
      done = true;
    } else {
      // We exclude EOF
      if (token.type == EOF) {
        done = true;
      } else {
        let tokenTypeName = lexer.symbolicNames[token.type];
        if (tokenTypeName === null) {
          tokenTypeName = 'symbols';
        }
        const smartRuleToken = new SmartRuleToken(tokenTypeName!, token.column);
        result.push(smartRuleToken);
      }
    }
  } while (!done);

  // Add all errors
  for (const e of errorStartingPoints) {
    const smartRuleToken = new SmartRuleToken('error', e);
    result.push(smartRuleToken);
  }

  result.sort((a, b) => (a.startIndex > b.startIndex ? 1 : -1));

  return result;
};
