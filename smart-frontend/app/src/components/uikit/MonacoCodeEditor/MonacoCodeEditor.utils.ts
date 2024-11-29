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

import type { MonacoCodeEditorAcceptedLanguages } from '@uikit/MonacoCodeEditor/MonacoCodeEditor.types';
import { monaco } from '@uikit/MonacoCodeEditor/MonacoCodeEditor.types';

export const unknownSchemaToMonacoEditorSchemas = (schema: unknown, modelUri: string) => {
  if (!schema) return undefined;
  return [
    {
      uri: modelUri,
      fileMatch: [modelUri], // associate with our model
      schema,
    },
  ];
};

export const initMonacoEditorModel = (
  modelUri: string,
  initialValue: string,
  language: MonacoCodeEditorAcceptedLanguages,
) => {
  const uri = monaco.Uri.parse(modelUri);
  let model = modelUri && monaco.editor.getModel(uri);

  if (model) {
    // Cannot create two models with the same URI,
    // if model with the given URI is already created, just update it.
    model.setValue(initialValue);
    monaco.editor.setModelLanguage(model, language);
  } else {
    model = monaco.editor.createModel(initialValue, language, uri);
  }

  return model;
};
