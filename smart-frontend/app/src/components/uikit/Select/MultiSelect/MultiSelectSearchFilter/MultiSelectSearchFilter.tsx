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
import { useMultiSelectContext } from '../MultiSelectContext/MultiSelect.context';
import CommonSelectSearchFilter from '@uikit/Select/CommonSelect/CommonSelectSearchFilter/CommonSelectSearchFilter';
import s from './MultiSelectSearchFilter.module.scss';
import Button from '@uikit/Button/Button';

const MultiSelectSearchFilter: React.FC = <T,>() => {
  const {
    originalOptions,
    options: filteredOptions,
    setOptions,
    onChange,
    searchPlaceholder,
  } = useMultiSelectContext<T>();

  const [search, setSearch] = useState('');

  const isFilterDisabled = search.length === 0 || filteredOptions.length === 0;
  const handleSelectFiltered = () => {
    const allFilteredList = filteredOptions.map(({ value }) => value);
    onChange(allFilteredList);
  };

  return (
    <div className={s.multiSelectSearchFilter} data-qa="search-filter">
      <CommonSelectSearchFilter
        originalOptions={originalOptions}
        setOptions={setOptions}
        searchPlaceholder={searchPlaceholder}
        className={s.multiSelectSearchFilter__select}
        onSearch={setSearch}
      />
      <Button disabled={isFilterDisabled} onClick={handleSelectFiltered}>
        Select filtered
      </Button>
    </div>
  );
};

export default MultiSelectSearchFilter;
