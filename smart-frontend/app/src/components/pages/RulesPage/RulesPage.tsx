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
import React from 'react';
import { FlexGroup, Title } from '@uikit';
import RulesToolbar from './RulesToolbar/RulesToolbar';
import RuleCreateBtn from './RuleCreateBtn/RuleCreateBtn';
import RulesTable from './RulesTable/RulesTable';
import { useRequestRules } from './useRequestRules';
import RulesDialogs from './RulesDialogs/RulesDialogs';
import RulesCards from './RulesCards/RulesCards';

const RulesPage: React.FC = () => {
  useRequestRules();

  return (
    <div>
      <FlexGroup gap="20px">
        <Title variant="h1">Rules</Title>
        <RuleCreateBtn />
      </FlexGroup>
      <RulesCards />
      <RulesToolbar />
      <RulesTable />
      <RulesDialogs />
    </div>
  );
};

export default RulesPage;
