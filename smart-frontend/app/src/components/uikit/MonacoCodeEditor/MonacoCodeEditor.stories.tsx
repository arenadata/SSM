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

import { useCallback, useEffect, useRef, useState } from 'react';
import MonacoCodeEditor from './MonacoCodeEditor';
import type { Meta, StoryObj } from '@storybook/react';
import { schema, jsonText } from './MonacoCodeEditor.stories.constants';

type Story = StoryObj<typeof MonacoCodeEditor>;

export default {
  title: 'uikit/MonacoCodeEditor',
  component: MonacoCodeEditor,
  argTypes: {},
} as Meta<typeof MonacoCodeEditor>;

const MonacoCodeEditorJsonExample = () => {
  const model = useRef({});

  const handleChange = useCallback((value: string) => {
    console.info(value);
    try {
      const parsed = JSON.parse(value);
      console.info(parsed);
      model.current = parsed;
    } catch (e) {
      console.error('json parse error', e);
    }
  }, []);

  return (
    <MonacoCodeEditor
      language="json"
      modelUri="http://myserver/foo.json"
      initialValue={jsonText}
      schema={schema}
      onChange={handleChange}
    />
  );
};

export const MonacoEditorJsonStory: Story = {
  args: {
    initialValue: jsonText,
  },
  render: () => {
    return (
      <div style={{ height: '500px' }}>
        <MonacoCodeEditorJsonExample />
      </div>
    );
  },
};

const MonacoCodeEditorSmartRuleExample = () => {
  const [value, setValue] = useState('');

  useEffect(() => {
    console.info(value);
  }, [value]);

  return (
    <MonacoCodeEditor
      language="ssmrule"
      modelUri="http://myserver/foo.json"
      initialValue={'file: at 5sec | path matches "/tmp/*.log" | read; delete'}
      theme="ssmruleTheme"
      schema={schema}
      onChange={setValue}
    />
  );
};

export const MonacoEditorSmartRuleStory: Story = {
  args: {
    initialValue: jsonText,
  },
  render: () => {
    return (
      <div style={{ height: '500px' }}>
        <MonacoCodeEditorSmartRuleExample />
      </div>
    );
  },
};
