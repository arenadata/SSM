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
import React, { useMemo, useRef, useState } from 'react';
import type { InputProps } from '@uikit/Input/Input';
import SingleSelectPanel from '@uikit/Select/SingleSelect/SingleSelectPanel/SingleSelectPanel';
import type { SingleSelectOptions } from '@uikit/Select/Select.types';
import { useForwardRef } from '@hooks/useForwardRef';
import CommonSelectField from '@uikit/Select/CommonSelect/CommonSelectField/CommonSelectField';
import PopoverPanelDefault from '@uikit/Popover/PopoverPanelDefault/PopoverPanelDefault';
import type { PopoverOptions } from '@uikit/Popover/Popover.types';
import Popover from '@uikit/Popover/Popover';

export type SelectProps<T> = SingleSelectOptions<T> &
  PopoverOptions &
  Omit<InputProps, 'endAdornment' | 'startAdornment' | 'readOnly' | 'onChange' | 'value'> & { dataTest?: string };

function SelectComponent<T>(
  {
    options,
    value,
    onChange,
    noneLabel,
    maxHeight,
    isSearchable,
    hasError,
    disabled,
    searchPlaceholder,
    containerRef,
    placement,
    offset,
    dependencyWidth = 'min-parent',
    dataTest = 'select-popover',
    ...props
  }: SelectProps<T>,
  ref: React.ForwardedRef<HTMLInputElement>,
) {
  const [isOpen, setIsOpen] = useState(false);
  const localContainerRef = useRef(null);
  const containerReference = useForwardRef(localContainerRef, containerRef);

  const handleChange = (val: T | null) => {
    setIsOpen(false);
    onChange?.(val);
  };

  const selectedOptionLabel = useMemo(() => {
    const currentOption = options.find(({ value: val }) => val === value);
    return currentOption?.label ?? '';
  }, [options, value]);

  return (
    <>
      <CommonSelectField
        {...props}
        ref={ref}
        onClick={() => setIsOpen((prev) => !prev)}
        onClear={() => handleChange(null)}
        isOpen={isOpen}
        value={selectedOptionLabel}
        containerRef={containerReference}
        hasError={hasError}
        disabled={disabled}
      />
      <Popover
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        triggerRef={localContainerRef}
        dependencyWidth={dependencyWidth}
        placement={placement}
        offset={offset}
      >
        <PopoverPanelDefault data-qa={dataTest}>
          <SingleSelectPanel
            options={options}
            value={value}
            onChange={handleChange}
            noneLabel={noneLabel}
            maxHeight={maxHeight}
            isSearchable={isSearchable}
            searchPlaceholder={searchPlaceholder}
          />
        </PopoverPanelDefault>
      </Popover>
    </>
  );
}

const Select = React.forwardRef(SelectComponent) as <T>(
  _props: SelectProps<T>,
  _ref: React.ForwardedRef<HTMLInputElement>,
) => ReturnType<typeof SelectComponent>;

export default Select;
