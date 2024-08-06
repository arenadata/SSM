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
import { format, intervalToDuration } from './index';
import { localDateToUtc } from './utcUtils';
import type { SerializedDate } from '@models/dateRange';

type DateToStringOptions = {
  toUtc?: boolean;
  format?: string;
};

export const dateToString = (date: Date, options: DateToStringOptions = {}) => {
  const { format: formatStr = 'dd/MM/yyyy HH:mm:ss', toUtc = false } = options;
  const d1 = toUtc ? localDateToUtc(date) : date;
  return format(d1, formatStr);
};

// TODO: talk about use '{days}d {hours}h {minutes}m {seconds}s'
export const dateDuration = (dateFrom: Date, dateTo: Date, format = '{days}d {hours}:{minutes}:{seconds}') => {
  const { days = 0, hours = 0, minutes = 0, seconds = 0 } = intervalToDuration({ start: dateFrom, end: dateTo });

  const prepHours = hours.toString().padStart(2, '0');
  const prepMinutes = minutes.toString().padStart(2, '0');
  const prepSeconds = seconds.toString().padStart(2, '0');

  let localFormat = format;
  if (days === 0) {
    localFormat = format.replace(/{days}.*{hours}/, '{hours}');
  }

  return localFormat
    .replace('{days}', `${days}`)
    .replace('{hours}', prepHours)
    .replace('{minutes}', prepMinutes)
    .replace('{seconds}', prepSeconds);
};

export const secondsToDuration = (seconds: number) => {
  const curDate = new Date(0);

  return dateDuration(curDate, new Date(curDate.getTime() + seconds * 1000));
};

export const millisecondsToDuration = (milliseconds: number) => {
  const curDate = new Date(0);

  return dateDuration(curDate, new Date(curDate.getTime() + milliseconds));
};

export const millisecondsToDate = (milliseconds: number): Date => {
  return new Date(milliseconds);
};

export const dateToMilliseconds = (date: Date): number => {
  if (date === null) return 0;
  return date.getTime();
};

export const deserializeDate = (milliseconds: SerializedDate): Date => millisecondsToDate(milliseconds);
export const serializeDate = (date: Date): SerializedDate => dateToMilliseconds(date);
