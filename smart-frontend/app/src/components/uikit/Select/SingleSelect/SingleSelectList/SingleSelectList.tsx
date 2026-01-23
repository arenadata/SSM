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
import React, { useMemo } from 'react';
import type { SelectOption } from '@uikit/Select/Select.types';
import s from './SingleSelectList.module.scss';
import cn from 'classnames';
import { useSingleSelectContext } from '../SingleSelectContext/SingleSelect.context';
import Tooltip from '@uikit/Tooltip/Tooltip';
import ConditionalWrapper from '@uikit/ConditionalWrapper/ConditionalWrapper';

const SingleSelectList = <T,>() => {
  const {
    //
    options: outerOptions,
    value: selectedValue,
    onChange,
    noneLabel,
    maxHeight,
    renderItem,
  } = useSingleSelectContext<T>();

  const options = useMemo(() => {
    if (!noneLabel) {
      return outerOptions;
    }

    return [
      {
        value: null,
        label: noneLabel,
        disabled: false,
      } as SelectOption<T>,
      ...outerOptions,
    ];
  }, [noneLabel, outerOptions]);

  return (
    <ul className={cn(s.singleSelectList, 'scroll')} style={{ maxHeight }} data-qa="options">
      {options.map(({ value, label, disabled, title }) => (
        <SingleSelectOptionsItem
          key={label.toString()}
          onSelect={() => {
            selectedValue !== value && onChange(value);
          }}
          isSelected={selectedValue === value}
          title={title}
          disabled={disabled}
        >
          {renderItem ? renderItem({ value, label, disabled, title }) : label}
        </SingleSelectOptionsItem>
      ))}
    </ul>
  );
};
export default SingleSelectList;

interface SingleSelectListItemProps {
  children: React.ReactNode;
  disabled?: boolean;
  title?: string;
  onSelect?: () => void;
  isSelected?: boolean;
}
const SingleSelectOptionsItem: React.FC<SingleSelectListItemProps> = ({
  onSelect,
  children,
  disabled,
  title,
  isSelected,
}) => {
  const handleClick = () => {
    if (disabled) return;
    onSelect?.();
  };
  const itemClass = cn(s.singleSelectListItem, {
    [s.singleSelectListItem_selected]: isSelected,
    [s.singleSelectListItem_disabled]: disabled,
  });

  return (
    <ConditionalWrapper Component={Tooltip} isWrap={!!title} label={title} placement={'bottom-start'}>
      <li className={itemClass} onClick={handleClick}>
        {children}
      </li>
    </ConditionalWrapper>
  );
};
