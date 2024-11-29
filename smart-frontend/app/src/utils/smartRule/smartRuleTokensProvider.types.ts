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
import TokensProvider = monaco.languages.TokensProvider;
export type { TokensProvider };

export class SmartRuleState implements IState {
  clone(): IState {
    return new SmartRuleState();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  equals(other: IState): boolean {
    return true;
  }
}

export class SmartRuleToken implements IToken {
  scopes: string;
  startIndex: number;

  constructor(ruleName: string, startIndex: number) {
    this.scopes = ruleName.toLowerCase() + '.ssmrule';
    this.startIndex = startIndex;
  }
}

export class SmartRuleLineTokens implements ILineTokens {
  endState: IState;
  tokens: IToken[];

  constructor(tokens: IToken[]) {
    this.endState = new SmartRuleState();
    this.tokens = tokens;
  }
}
