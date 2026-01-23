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
import CommonSelectNoResult from '@uikit/Select/CommonSelect/CommonSelectNoResult/CommonSelectNoResult';
import MultiSelectFullCheckAll from '@uikit/Select/MultiSelect/MultiSelectFullCheckAll/MultiSelectFullCheckAll';
import type { MultiSelectOptions } from '@uikit/Select/Select.types';
import { MultiSelectContextProvider } from '../MultiSelectContext/MultiSelectContextProvider';
import { useMultiSelectContext } from '../MultiSelectContext/MultiSelect.context';
import MultiSelectList from '../MultiSelectList/MultiSelectList';
import MultiSelectSearchFilter from '../MultiSelectSearchFilter/MultiSelectSearchFilter';
import s from './MultiSelectPanel.module.scss';
import cn from 'classnames';

const MultiSelectContent = <T,>() => {
  const { isSearchable, options, checkAllLabel, compactMode } = useMultiSelectContext<T>();
  const isShowOptions = options.length > 0;
  const hasCheckAll = !!checkAllLabel;
  return (
    <>
      {hasCheckAll && (
        <div
          className={cn(s.multiSelectPanel__section, {
            [s.multiSelectPanel__section_compactMode]: compactMode,
          })}
          data-qa="check-all"
        >
          <MultiSelectFullCheckAll />
        </div>
      )}
      <div
        className={cn(s.multiSelectPanel__section, {
          [s.multiSelectPanel__section_compactMode]: compactMode,
        })}
      >
        {isSearchable && <MultiSelectSearchFilter />}
        <div data-qa="options-container">{isShowOptions ? <MultiSelectList /> : <CommonSelectNoResult />}</div>
      </div>
    </>
  );
};

const MultiSelectPanel = <T,>(props: MultiSelectOptions<T>) => {
  return (
    <div className={s.multiSelectPanel}>
      <MultiSelectContextProvider value={props}>
        <MultiSelectContent />
      </MultiSelectContextProvider>
    </div>
  );
};

export default MultiSelectPanel;
