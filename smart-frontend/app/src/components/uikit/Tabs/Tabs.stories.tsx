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
import React from 'react';
import type { Meta, StoryObj } from '@storybook/react';
import type { TabsBlockProps } from '@uikit/Tabs/TabsBlock';
import TabsBlock from '@uikit/Tabs/TabsBlock';
import Tab from '@uikit/Tabs/Tab';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom';

const pageStyles = {
  marginTop: '30px',
  fontSize: '30px',
  lineHeight: '2em',
};

const easyTabsPages = [
  {
    path: '/tab1',
    content: 'Tab 1',
  },
  {
    path: '/tab2',
    content: 'Tab 2',
  },
];

type Story = StoryObj<typeof TabsBlock>;

export default {
  title: 'uikit/Tabs',
  component: TabsBlock,
  decorators: [
    (Story, context) => {
      return (
        <MemoryRouter
          initialEntries={context.parameters.pages.map(({ path }: { path: string }) => path)}
          initialIndex={0}
        >
          <Story />
          <Routes>
            {context.parameters.pages.map(({ path, content }: { path: string; content: string }) => (
              <Route path={path} element={<div style={pageStyles}>{content}</div>} key={path} />
            ))}
          </Routes>
        </MemoryRouter>
      );
    },
  ],
  argTypes: {
    children: {
      table: {
        disable: true,
      },
    },
    variant: {
      table: {
        disable: true,
      },
    },
  },
} as Meta<typeof TabsBlock>;

const TabsExample: React.FC<TabsBlockProps> = (args) => {
  return (
    <div>
      <TabsBlock {...args}>
        <Tab to="/tab1">Home</Tab>
        <Tab to="/tab2">About</Tab>
      </TabsBlock>
      <Outlet />
    </div>
  );
};

export const TabsStory: Story = {
  parameters: {
    pages: easyTabsPages,
  },
  render: (args) => {
    return <TabsExample {...args} />;
  },
};
