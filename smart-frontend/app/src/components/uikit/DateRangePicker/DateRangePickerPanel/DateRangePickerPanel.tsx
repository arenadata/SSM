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
import TabsBlock from '@uikit/Tabs/TabsBlock';
import TabButton from '@uikit/Tabs/TabButton';
import RangesTab from '../Tabs/RangesTab';
import CalendarTab from '../Tabs/CalendarTab';
import type { RangePreset } from '../DateRangePicker.types';
import { defaultRangesPreset } from '../DateRangePicker.constants';
import { type DateRange, type DynamicDateRange, isDynamicDateRange, isStaticDateRange } from '@models/dateRange';

type DatePickerTabs = 'range' | 'calendar';

export interface DateRangePickerPanelProps {
  range?: DateRange;
  onApply: (range: DateRange) => void;
  onRevert: () => void;
  rangesPreset?: RangePreset[];
}

const DateRangePickerPanel: React.FC<DateRangePickerPanelProps> = ({
  range,
  onApply,
  onRevert,
  rangesPreset = defaultRangesPreset,
}) => {
  const [activeTab, setActiveTab] = useState<DatePickerTabs>(() => {
    return isStaticDateRange(range) ? 'calendar' : 'range';
  });

  const getHandleTabClick = (tabName: DatePickerTabs) => () => {
    setActiveTab(tabName);
  };

  const handleApplyDynamicRange = (range: DynamicDateRange) => {
    onApply(range);
  };

  const handleApplyStaticDateRange = (from: Date, to: Date) => {
    onApply({ from, to });
  };

  return (
    <div data-qa="data-picker-panel">
      <TabsBlock variant="secondary">
        <TabButton onClick={getHandleTabClick('range')} isActive={activeTab === 'range'}>
          Range
        </TabButton>
        <TabButton onClick={getHandleTabClick('calendar')} isActive={activeTab === 'calendar'}>
          Calendar
        </TabButton>
      </TabsBlock>
      {activeTab === 'range' && (
        <RangesTab
          range={isDynamicDateRange(range) ? range : undefined}
          onApply={handleApplyDynamicRange}
          onRevert={onRevert}
          rangesPreset={rangesPreset}
        />
      )}
      {activeTab === 'calendar' && (
        <CalendarTab
          rangeFrom={isStaticDateRange(range) ? range.from : undefined}
          rangeTo={isStaticDateRange(range) ? range.to : undefined}
          onApply={handleApplyStaticDateRange}
          onRevert={onRevert}
        />
      )}
    </div>
  );
};

export default DateRangePickerPanel;
