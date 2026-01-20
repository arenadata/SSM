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
import React, { useEffect, useState } from 'react';
import cn from 'classnames';
import { localDateToUtc } from '@utils/date/utcUtils';
import { format } from '@utils/date';

import s from './CurrentDate.module.scss';

type FormattedDateType = {
  date: string;
  time: string;
};

const getFormattedCurrentDate = () => {
  const curDate = localDateToUtc(new Date());

  return {
    date: format(curDate, 'dd MMM yyyy'),
    time: format(curDate, 'HH:mm:ss'),
  };
};

const CurrentDate: React.FC = () => {
  const [formattedDate, setFormattedDate] = useState<FormattedDateType>(getFormattedCurrentDate);

  useEffect(() => {
    const interval = setInterval(() => setFormattedDate(getFormattedCurrentDate()), 1000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className={s.currentDate}>
      <div data-qa="current-date" className={s.currentDate__item}>
        {formattedDate.date}
      </div>
      <div data-qa="current-time" className={cn(s.currentDate__item, s.currentDate__item_time)}>
        {formattedDate.time}
      </div>
      <div data-qa="current-time-zone" className={s.currentDate__item}>
        UTC
      </div>
    </div>
  );
};

export default CurrentDate;
