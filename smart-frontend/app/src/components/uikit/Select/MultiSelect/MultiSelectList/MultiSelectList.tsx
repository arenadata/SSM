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
import type { ChangeEvent } from 'react';
import React from 'react';
import { useMultiSelectContext } from '../MultiSelectContext/MultiSelect.context';
import Checkbox from '@uikit/Checkbox/Checkbox';
import s from './MultiSelectList.module.scss';
import cn from 'classnames';
import ConditionalWrapper from '@uikit/ConditionalWrapper/ConditionalWrapper';
import Tooltip from '@uikit/Tooltip/Tooltip';

const MultiSelectList = <T,>() => {
  const {
    //
    options,
    value: selectedValues,
    onChange,
    maxHeight,
  } = useMultiSelectContext<T>();

  const getHandleChange = (value: T) => (e: ChangeEvent<HTMLInputElement>) => {
    const valueIndex = selectedValues.indexOf(value);
    const newSelectedValues = [...selectedValues];

    if (e.target.checked && valueIndex === -1) {
      newSelectedValues.push(value);
    } else if (!e.target.checked && valueIndex > -1) {
      newSelectedValues.splice(valueIndex, 1);
    }

    onChange(newSelectedValues);
  };

  return (
    <ul className={cn(s.multiSelectList, 'scroll')} style={{ maxHeight }} data-qa="options">
      {options.map(({ value, label, disabled, title }) => (
        <ConditionalWrapper
          key={label?.toString() + value}
          Component={Tooltip}
          isWrap={!!title}
          label={title}
          placement="bottom-start"
        >
          <li className={s.multiSelectList__item}>
            <Checkbox
              label={label}
              disabled={disabled}
              checked={selectedValues.includes(value)}
              onChange={getHandleChange(value)}
              className={s.multiSelectList__checkbox}
            />
          </li>
        </ConditionalWrapper>
      ))}
    </ul>
  );
};

export default MultiSelectList;
