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

import type { Meta, StoryFn } from '@storybook/react';
import { SimpleLogView } from '@uikit';

/* eslint-disable */
const testLog =
  '          -rw-r--r--      3 tigrulya     hadoop      536870912 2024-01-22 12:40 tmp/.another_tmp\n' +
  '-rw-r--r--      3 tigrulya     hadoop      157286400 2024-03-19 09:58 /tmp/1.txt\n' +
  'drwxr-xr-x      0 dr.who       hadoop      0 2024-03-18 12:40 /tmp/ADH-4175\n' +
  'drwxr-xr-x      0 dr.who       hadoop      0 2024-03-13 10:55 /tmp/ADH-double-copy\n' +
  'drwxr-xr-x      0 dr.who       hadoop      0 2024-02-13 15:04 /tmp/ADH_4064\n' +
  '-rw-r--r--      3 tigrulya     hadoop      184122927 2023-09-21 12:54 /tmp/BACKUP_smart-data-14.6.0-SNAPSHOT.tar.gz\n' +
  '-rw-r--r--      3 tigrulya     hadoop         144123 2023-10-10 09:49 /tmp/LICENSE.txt\n' +
  'drwxr-xr-x      0 tigrulya     hadoop              0 2024-01-19 14:03 /tmp/another_dest\n' +
  'drwxr-xr-x      0 tigrulya     hadoop              0 2024-02-08 08:23 /tmp/arch.har\n' +
  'drwxr-xr-x      0 tigrulya     hadoop              0 2024-10-03 14:20 /tmp/check';
/* eslint-enable */

export default {
  title: 'uikit/SimpleLogView',
  component: SimpleLogView,
  argTypes: {},
} as Meta<typeof SimpleLogView>;

const Template: StoryFn<typeof SimpleLogView> = (args) => {
  return <SimpleLogView {...args} log={testLog} />;
};

export const SimpleLogViewElement = Template.bind({});
