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
import { useState } from 'react';
import TabActions from './TabActions';
import ts from './Tabs.module.scss';
import s from './RangesTab.module.scss';
import cn from 'classnames';
import FormField from '@uikit/FormField/FormField';
import Input from '@uikit/Input/Input';
import type { RangePreset } from '../DateRangePicker.types';
import type { DynamicDateRange } from '@models/dateRange';

interface RangesTabProps {
  range?: DynamicDateRange;
  onApply: (range: DynamicDateRange) => void;
  onRevert: () => void;
  rangesPreset: RangePreset[];
}

const RangesTab = ({ range, onApply, onRevert, rangesPreset }: RangesTabProps) => {
  const [selectedRangeId, setSelectedRangeId] = useState<DynamicDateRange>(range ?? rangesPreset[0].id);

  const handleClick = (item: RangePreset) => {
    setSelectedRangeId(item.id);
  };

  const handleApply = () => {
    onApply(selectedRangeId);
  };

  return (
    <div className={ts.dateRangePickerTab}>
      <div className={cn(ts.dateRangePickerTab__left, s.rangesPreset, 'scroll')}>
        {rangesPreset.map((item) => {
          const className = cn(s.rangesPreset__buttons, {
            [s.rangesPreset__buttons_selected]: item.id === selectedRangeId,
          });

          return (
            <button tabIndex={-1} key={item.id} className={className} onClick={() => handleClick(item)}>
              {item.description}
            </button>
          );
        })}
      </div>
      <div className={ts.dateRangePickerTab__right}>
        <div className={ts.dateRangePickerTab__rightInputs}>
          <FormField label="From">
            <Input size="small" value={selectedRangeId} readOnly />
          </FormField>
          <FormField label="To">
            <Input size="small" value="now" readOnly />
          </FormField>
        </div>
        <TabActions onApply={handleApply} onRevert={onRevert} />
      </div>
    </div>
  );
};

export default RangesTab;
