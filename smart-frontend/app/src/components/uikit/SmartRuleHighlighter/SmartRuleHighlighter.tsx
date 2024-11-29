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
import { getTokens } from '@utils/smartRule/smartRuleTokensProvider.utils';
import s from './SmartRuleHighlighter.module.scss';
import cn from 'classnames';

export interface SmartRuleHighlighterProps {
  rule: string;
}

const SmartRuleHighlighter = ({ rule }: SmartRuleHighlighterProps) => {
  const tokens = getTokens(rule);
  const elements: React.ReactElement[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const nextToken = tokens[i + 1];

    let spacesCount = 0;
    let cursor = token.startIndex;
    for (; cursor < (nextToken?.startIndex || rule.length); cursor++) {
      if (rule[cursor] === ' ') {
        spacesCount += 1;
      }
    }

    const tokenText = rule.substring(token.startIndex, cursor - spacesCount);
    elements.push(
      <span key={`${i}-token`} className={cn(s.token, s[token.scopes])}>
        {tokenText}
      </span>,
    );

    if (spacesCount) {
      elements.push(
        <span key={`${i}-space`} className={cn(s.token)}>
          {'\u00A0'.repeat(spacesCount)}
        </span>,
      );
    }
  }

  return <span className={s.smartRuleHighlighter}>{elements}</span>;
};

export default SmartRuleHighlighter;
