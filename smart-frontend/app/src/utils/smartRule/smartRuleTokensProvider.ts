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

import * as monaco from 'monaco-editor/esm/vs/editor/editor.api';
import ILineTokens = monaco.languages.ILineTokens;
import IToken = monaco.languages.IToken;
import IState = monaco.languages.IState;
import type { TokensProvider } from './smartRuleTokensProvider.types';
import { SmartRuleLineTokens, SmartRuleState } from './smartRuleTokensProvider.types';
import { getTokens } from './smartRuleTokensProvider.utils';

export class SmartRuleTokensProvider implements TokensProvider {
  getInitialState(): IState {
    return new SmartRuleState();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  tokenize(line: string, state: IState): ILineTokens {
    // So far we ignore the state, which is not great for performance reasons
    return tokensForLine(line);
  }
}

export function tokensForLine(input: string): monaco.languages.ILineTokens {
  const tokens: IToken[] = getTokens(input);
  return new SmartRuleLineTokens(tokens);
}
