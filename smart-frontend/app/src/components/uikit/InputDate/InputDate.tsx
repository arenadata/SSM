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
import { format, isValid } from '@utils/date';
import React, { useEffect, useState } from 'react';
import s from './InputDate.module.scss';
import cn from 'classnames';
import { useFieldStyles } from '@uikit/Field/useFieldStyles';

interface InputDateProps {
  value?: Date;
  tabIndex?: number;
  onChange: (date: Date) => void;
  setHasError?: (hasError: boolean) => void;
  dataTest?: string;
}

const InputDate = ({ value, tabIndex, onChange, dataTest }: InputDateProps) => {
  const [day, setDay] = useState(value ? format(value, 'dd') : '--');
  const [month, setMonth] = useState(value ? format(value, 'MM') : '--');
  const [year, setYear] = useState(value ? format(value, 'yyyy') : '--');
  const [hours, setHours] = useState(value ? format(value, 'HH') : '--');
  const [minutes, setMinutes] = useState(value ? format(value, 'mm') : '--');
  const [seconds, setSeconds] = useState(value ? format(value, 'ss') : '--');

  const localTabIndex = (tabIndex ?? 1) * 10;

  useEffect(() => {
    setDay(value ? format(value, 'dd') : '--');
    setMonth(value ? format(value, 'MM') : '--');
    setYear(value ? format(value, 'yyyy') : '--');
    setHours(value ? format(value, 'HH') : '--');
    setMinutes(value ? format(value, 'mm') : '--');
    setSeconds(value ? format(value, 'ss') : '--');
  }, [value]);

  const handleChangeDate = (event: React.ChangeEvent<HTMLInputElement>) => {
    const unit = event.currentTarget.dataset.inputId;
    switch (unit) {
      case 'day':
        if (event.target.value.length <= 2) {
          setDay(event.target.value);
        }
        break;
      case 'month':
        if (event.target.value.length <= 2) {
          setMonth(event.target.value);
        }
        break;
      case 'year':
        if (event.target.value.length <= 4) {
          setYear(event.target.value);
        }
        break;
      case 'hours':
        if (event.target.value.length <= 2) {
          setHours(event.target.value);
        }
        break;
      case 'minutes':
        if (event.target.value.length <= 2) {
          setMinutes(event.target.value);
        }
        break;
      case 'seconds':
        if (event.target.value.length <= 2) {
          setSeconds(event.target.value);
        }
        break;
    }
  };

  const updateDate = () => {
    const updatedDate = new Date(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hours),
      Number(minutes),
      Number(seconds),
    );
    if (isValid(updatedDate)) {
      onChange(updatedDate);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      updateDate();
    }

    if (event.currentTarget.dataset.inputId === 'seconds' && event.key === 'Tab') {
      updateDate();
    }
  };

  const handleBlur = () => {
    updateDate();
  };

  const { fieldClasses } = useFieldStyles({ hasError: false, disabled: false });

  return (
    <div onBlur={handleBlur} className={s.InputDate} data-qa={dataTest}>
      <span className={cn(fieldClasses, s.InputDate__inputs)}>
        <span className={s.InputDate__date}>
          <input
            tabIndex={localTabIndex + 1}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={day}
            className={cn(s.InputDate__input, s.InputDate__input_day)}
            data-input-id="day"
          />
          <span className={s.InputDate__delimiter}>/</span>
          <input
            tabIndex={localTabIndex + 2}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={month}
            className={cn(s.InputDate__input, s.InputDate__input_month)}
            data-input-id="month"
          />
          <span className={s.InputDate__delimiter}>/</span>
          <input
            tabIndex={localTabIndex + 3}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={year}
            className={cn(s.InputDate__input, s.InputDate__input_year)}
            data-input-id="year"
          />
        </span>
        <span className={s.InputDate__time}>
          <input
            tabIndex={localTabIndex + 4}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={hours}
            className={cn(s.InputDate__input, s.InputDate__input_hours)}
            data-input-id="hours"
          />
          <span className={s.InputDate__delimiter}>:</span>
          <input
            tabIndex={localTabIndex + 5}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={minutes}
            className={cn(s.InputDate__input, s.InputDate__input_minutes)}
            data-input-id="minutes"
          />
          <span className={s.InputDate__delimiter}>:</span>
          <input
            tabIndex={localTabIndex + 6}
            onChange={handleChangeDate}
            onKeyDown={handleKeyDown}
            value={seconds}
            className={cn(s.InputDate__input, s.InputDate__input_seconds)}
            data-input-id="seconds"
          />
        </span>
      </span>
    </div>
  );
};

export default InputDate;
