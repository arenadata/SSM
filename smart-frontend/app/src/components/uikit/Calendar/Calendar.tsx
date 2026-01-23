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
import { useState, useMemo } from 'react';
import CalendarHeader from './CalendarHeader/CalendarHeader';
import CalendarGrid from './CalendarGrid/CalendarGrid';
import type { MonthSwitchDirections } from './Calendar.types';
import { getCalendarMap } from './Calendar.utils';
import { getToday, addMonths } from '@utils/date/calendarUtils';
import s from './Calendar.module.scss';

export interface CalendarProps {
  date?: Date;
  rangeFrom?: Date;
  rangeTo?: Date;
  onDateClick: (date: Date) => void;
}

const Calendar = ({ date, rangeFrom, rangeTo, onDateClick }: CalendarProps) => {
  const [selectedMonth, setSelectedMonth] = useState(date ?? getToday());

  const handleMonthChange = (direction: MonthSwitchDirections) => () => {
    setSelectedMonth(direction === 'prev' ? addMonths(selectedMonth, -1) : addMonths(selectedMonth, 1));
  };

  const calendarMap = useMemo(() => getCalendarMap(selectedMonth), [selectedMonth]);

  return (
    <div className={s.calendar}>
      <div className={s.calendar__section} data-qa="calendar-header">
        <CalendarHeader onMonthChange={handleMonthChange} month={selectedMonth} />
      </div>
      <div className={s.calendar__section} data-qa="calendar-days">
        <CalendarGrid
          calendarMap={calendarMap}
          onDateClick={onDateClick}
          rangeFrom={rangeFrom}
          rangeTo={rangeTo}
          selectedDate={date}
          selectedMonth={selectedMonth}
        />
      </div>
    </div>
  );
};

export default Calendar;
