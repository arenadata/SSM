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
import AuditEventsResetFilter from '../AuditEventsResetFilter/AuditEventsResetFilter';
import Pagination from '@uikit/Pagination/Pagination';
import { useDispatch, useStore } from '@hooks';
import type { PaginationParams } from '@models/table';
import { setAuditEventsPaginationParams, setRequestFrequency } from '@store/adh/auditEvents/auditEventsTableSlice';
import s from './AuditEventsToolbar.module.scss';
import { FlexGroup } from '@uikit';
import FrequencySelect from '@uikit/Table/FrequencySelect/FrequencySelect';

const AuditEventsToolbar: React.FC = () => {
  const dispatch = useDispatch();
  const auditEvents = useStore(({ adh }) => adh.auditEvents.auditEvents);
  const paginationParams = useStore(({ adh }) => adh.auditEventsTable.paginationParams);
  const requestFrequency = useStore(({ adh }) => adh.auditEventsTable.requestFrequency);

  const handlePaginationChange = (params: PaginationParams) => {
    dispatch(setAuditEventsPaginationParams(params));
  };

  const handleFrequencyChange = (frequency: number) => {
    dispatch(setRequestFrequency(frequency));
  };

  return (
    <FlexGroup gap="20px" className={s.auditEventsToolbar}>
      <AuditEventsResetFilter />
      <Pagination
        isNextBtn={auditEvents.length === paginationParams.perPage}
        pageData={paginationParams}
        onChangeData={handlePaginationChange}
        frequencyComponent={<FrequencySelect value={requestFrequency} onChange={handleFrequencyChange} />}
      />
    </FlexGroup>
  );
};

export default AuditEventsToolbar;
