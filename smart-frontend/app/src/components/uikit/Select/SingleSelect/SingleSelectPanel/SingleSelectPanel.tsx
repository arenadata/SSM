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
import type { SingleSelectOptions } from '../../Select.types';
import SingleSelectList from '../SingleSelectList/SingleSelectList';
import s from './SingleSelectPanel.module.scss';
import SingleSelectSearchFilter from '../SingleSelectSearchFilter/SingleSelectSearchFilter';
import CommonSelectNoResult from '@uikit/Select/CommonSelect/CommonSelectNoResult/CommonSelectNoResult';
import { SingleSelectContextProvider } from '../SingleSelectContext/SingleSelectContextProvider';
import { useSingleSelectContext } from '../SingleSelectContext/SingleSelect.context';

export type SingleSelectPanelProps<T> = SingleSelectOptions<T>;

function SingleSelectPanel<T>(props: SingleSelectPanelProps<T>) {
  return (
    <div className={s.singleSelectPanel}>
      <SingleSelectContextProvider value={props}>
        <SingleSelectContent />
      </SingleSelectContextProvider>
    </div>
  );
}

export default SingleSelectPanel;

const SingleSelectContent = <T,>() => {
  const { isSearchable, options } = useSingleSelectContext<T>();
  const isShowOptions = options.length > 0;
  return (
    <>
      {isSearchable && (
        <div data-qa="search-filter">
          <SingleSelectSearchFilter />
        </div>
      )}
      {isShowOptions ? <SingleSelectList /> : <CommonSelectNoResult />}
    </>
  );
};
