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
import Text from '@uikit/Text/Text';
import type { Meta, StoryObj } from '@storybook/react';

type Story = StoryObj<typeof Text>;
export default {
  title: 'uikit/Text',
  component: Text,
  argTypes: {
    variant: {
      description: 'Variant',
      defaultValue: 'h1',
      options: ['h1', 'h2', 'h3', 'h4'],
      control: { type: 'radio' },
    },
    className: {
      table: {
        disable: true,
      },
    },
  },
} as Meta<typeof Text>;

export const TextElement: Story = {
  args: {
    variant: 'h1',
  },
  render: (args) => {
    return <Text {...args}>Something text</Text>;
  },
};
