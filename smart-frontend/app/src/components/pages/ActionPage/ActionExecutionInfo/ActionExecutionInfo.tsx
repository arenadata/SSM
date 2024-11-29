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
import React, { useState } from 'react';
import s from './ActionExecutionInfo.module.scss';
import { SimpleLogView, TabsBlock, Tab } from '@uikit';
import { useStore } from '@hooks';

enum InfoTabs {
  Result = 'Result',
  Log = 'Log',
}

const ActionExecutionInfo = () => {
  const action = useStore((s) => s.adh.action.action);
  const [activeTab, setActiveTab] = useState<InfoTabs>(InfoTabs.Result);
  const [simpleLogData, setSimpleLogData] = useState<string>(action?.result || '');

  const logTabHandler = () => {
    setActiveTab(InfoTabs.Log);
    setSimpleLogData(action?.log || '');
  };

  const resultTabHandler = () => {
    setActiveTab(InfoTabs.Result);
    setSimpleLogData(action?.result || '');
  };

  return (
    <div className={s.actionExecutionInfo}>
      <TabsBlock>
        <Tab to="" isActive={activeTab === InfoTabs.Result} onClick={resultTabHandler}>
          Result
        </Tab>
        <Tab to="" isActive={activeTab === InfoTabs.Log} onClick={logTabHandler}>
          Log
        </Tab>
      </TabsBlock>
      {simpleLogData && <SimpleLogView className={s.actionExecutionInfo__logView} log={simpleLogData} />}
    </div>
  );
};

export default ActionExecutionInfo;
