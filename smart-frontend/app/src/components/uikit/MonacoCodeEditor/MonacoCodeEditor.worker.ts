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

/* eslint-disable-next-line import/no-unresolved */
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
/* eslint-disable-next-line import/no-unresolved */
import jsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker';

// todo: minimize by following
// https://github.com/microsoft/monaco-editor/blob/main/samples/browser-esm-webpack-small/index.js

self.MonacoEnvironment = {
  getWorker(_: unknown, label: string) {
    switch (label) {
      // Handle other cases
      case 'json':
        return new jsonWorker();
      default:
        console.warn(`Unknown label ${label}`);
        return new editorWorker();
    }
  },
};
