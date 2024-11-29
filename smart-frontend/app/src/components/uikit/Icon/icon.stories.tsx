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
import Icon from './Icon';
import type { Meta, StoryObj } from '@storybook/react';
import { allowIconsNames } from './sprite';
import s from './icon.stories.module.scss';

type Story = StoryObj<typeof Icon>;

export default {
  title: 'uikit/Icon',
  component: Icon,
  argTypes: {
    disabled: {
      description: 'Disabled',
      control: { type: 'boolean' },
    },
    startAdornment: {
      table: {
        disable: true,
      },
    },
    endAdornment: {
      table: {
        disable: true,
      },
    },
    variant: {
      table: {
        disable: true,
      },
    },
    placeholder: {
      control: { type: 'text' },
    },
  },
} as Meta<typeof Icon>;

const iconSize = 34;

export const IconsList: Story = {
  args: {},
  render: () => {
    const copyHandler = (iconName: string) => {
      navigator.clipboard.writeText(iconName);
    };

    return (
      <div className={s.iconsContainer}>
        <div>Click to copy icon name.</div>
        <div className={s.iconsWrapper}>
          {allowIconsNames.map((iconName) => (
            <div className={s.iconWrapper} onClick={() => copyHandler(iconName)}>
              <Icon name={iconName} size={iconSize} />
              <div>{iconName}</div>
            </div>
          ))}
        </div>
      </div>
    );
  },
};
