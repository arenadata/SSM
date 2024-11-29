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
import { type IconsNames, Icon, Title } from '@uikit';
import { AdhActionState } from '@models/adh';
import s from './ActionHeader.module.scss';
import { getActionHeaderData } from '@pages/ActionPage/ActionHeader/ActionHeader.utils';
import { useStore } from '@hooks';

const actionStateToIconName: Record<AdhActionState, IconsNames> = {
  [AdhActionState.Failed]: 'status-failed',
  [AdhActionState.Running]: 'status-running',
  [AdhActionState.Successful]: 'status-ok',
};

const ActionHeader = () => {
  const action = useStore((s) => s.adh.action.action);

  if (!action) return null;

  const { title, subtitle } = getActionHeaderData(action.textRepresentation);

  return (
    <div className={s.actionHeader}>
      <div className={s.actionHeader__titleWrapper}>
        <Title variant="h1">{title}</Title>
        {action.state && <Icon name={actionStateToIconName[action.state]} size={16} />}
      </div>
      <div className={s.actionHeader__text}>{subtitle}</div>
    </div>
  );
};

export default ActionHeader;
