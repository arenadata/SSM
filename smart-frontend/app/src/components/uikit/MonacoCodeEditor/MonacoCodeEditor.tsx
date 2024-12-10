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

import { useRef, useEffect, useState, useCallback } from 'react';
import { monaco } from './MonacoCodeEditor.types';
import type {
  ITextModel,
  IMarker,
  MonacoCodeEditorWidget,
  IPosition,
  MonacoCodeEditorAcceptedLanguages,
  IStandaloneCodeEditor,
} from './MonacoCodeEditor.types';
import './MonacoCodeEditor.worker';
import s from './MonacoCodeEditor.module.scss';
import smartRuleHighlighterStyles from '@uikit/SmartRuleHighlighter/SmartRuleHighlighter.module.scss';
import CodeEditorV3Problems from './MonacoCodeEditorProblems/MonacoCodeEditorProblems';
import CodeEditorV3Widgets from './MonacoCodeEditorWidgets';
import { SmartRuleTokensProvider } from '@utils/smartRule/smartRuleTokensProvider';
import { initMonacoEditorModel, unknownSchemaToMonacoEditorSchemas } from './MonacoCodeEditor.utils';

export interface MonacoCodeEditorProps {
  modelUri?: string;
  initialValue: string;
  glyphMargin?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema?: any;
  theme?: string;
  showMinimap?: boolean;
  language: MonacoCodeEditorAcceptedLanguages;
  validate?: boolean;
  widgets?: MonacoCodeEditorWidget[];
  isReadOnly?: boolean;
  onMount?: (editor: IStandaloneCodeEditor) => void;
  onUnmount?: (editor: IStandaloneCodeEditor) => void;
  onChange: (value: string, event: monaco.editor.IModelContentChangedEvent) => void;
  onModelChange?: (model: ITextModel) => Promise<void>;
  onMarkersChange?: (markers: IMarker[]) => void;
}

const modelUri = 'http://myserver/foo.json';

const MonacoCodeEditor = ({
  initialValue,
  // modelUri = 'http://myserver/foo.json', // as we editing single document per time
  glyphMargin,
  schema,
  language,
  theme = 'vs-dark',
  showMinimap = true,
  validate = true,
  widgets,
  isReadOnly = false,
  onMount,
  onUnmount,
  onChange,
  onModelChange,
  onMarkersChange,
}: MonacoCodeEditorProps) => {
  const editorRef = useRef<IStandaloneCodeEditor | null>();
  const modelRef = useRef<ITextModel>();

  const subscriptionRef = useRef<monaco.IDisposable>();
  const containerRef = useRef(null);

  const [markers, setMarkers] = useState<IMarker[]>([]);

  useEffect(() => {
    modelRef.current = initMonacoEditorModel(modelUri, initialValue, language);

    modelRef.current.onDidChangeContent(async () => {
      if (modelRef.current) {
        await onModelChange?.(modelRef.current);
      }
    });
    // ignore initialValue
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modelUri, language, onModelChange]);

  useEffect(() => {
    if (containerRef.current && modelRef.current) {
      editorRef.current = monaco.editor.create(containerRef.current!, {
        glyphMargin,
        model: modelRef.current,
        automaticLayout: true,
        theme,
        minimap: { enabled: showMinimap },
      });

      monaco.editor.onDidChangeMarkers(([resource]) => {
        const markers = monaco.editor.getModelMarkers({ resource });
        setMarkers(markers);
        onMarkersChange?.(markers);
      });

      onMount?.(editorRef.current);
    }

    if (modelRef.current) {
      onModelChange?.(modelRef.current);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // init schema
  useEffect(() => {
    const schemas = unknownSchemaToMonacoEditorSchemas(schema, modelUri);

    if (language === 'json' && schema) {
      // configure the JSON language support with schemas and schema associations
      monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
        validate,
        schemas,
      });
    }
  }, [schema, validate, language]);

  useEffect(() => {
    if (!editorRef.current) return;

    editorRef.current.updateOptions({
      readOnly: isReadOnly,
    });
  }, [isReadOnly]);

  useEffect(() => {
    return () => {
      onUnmount?.(editorRef.current!);
      subscriptionRef.current?.dispose();
      editorRef.current?.dispose();
      modelRef.current?.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (onChange) {
      subscriptionRef.current?.dispose();
      subscriptionRef.current = editorRef.current?.onDidChangeModelContent((event) => {
        onChange(editorRef.current?.getValue() || '', event);
      });
    }
  }, [onChange]);

  const handleProblemClick = useCallback((position: IPosition) => {
    editorRef.current?.setPosition(position);
    editorRef.current?.focus();
  }, []);

  return (
    <div className={s.editorWrapper}>
      <div className={s.editor} ref={containerRef} />
      <CodeEditorV3Problems markers={markers} onProblemClick={handleProblemClick} />
      <CodeEditorV3Widgets widgets={widgets} />
    </div>
  );
};

monaco.languages.register({ id: 'ssmrule' });
monaco.languages.setTokensProvider('ssmrule', new SmartRuleTokensProvider());
monaco.editor.defineTheme('ssmruleTheme', {
  base: 'vs-dark',
  inherit: false,
  colors: {},
  rules: [
    /* eslint-disable spellcheck/spell-checker */
    { token: 'objecttype.ssmrule', foreground: smartRuleHighlighterStyles.syntaxLiteral, fontStyle: 'bold' },
    { token: 'id.ssmrule', foreground: smartRuleHighlighterStyles.syntaxId },
    { token: 'matches.ssmrule', foreground: smartRuleHighlighterStyles.syntaxMatches, fontStyle: 'bold' },
    { token: 'string.ssmrule', foreground: smartRuleHighlighterStyles.syntaxString, fontStyle: 'italic' },
    { token: 'symbols.ssmrule', foreground: smartRuleHighlighterStyles.syntaxSymbols },
    { token: 'opeq.ssmrule', foreground: smartRuleHighlighterStyles.syntaxCompare },
    { token: 'opcmp.ssmrule', foreground: smartRuleHighlighterStyles.syntaxCompare },
    { token: 'or.ssmrule', foreground: smartRuleHighlighterStyles.syntaxSymbols },
    { token: 'and.ssmrule', foreground: smartRuleHighlighterStyles.syntaxSymbols },
    { token: 'unrecognized.ssmrule', foreground: smartRuleHighlighterStyles.syntaxError },
    { token: 'error.ssmrule', foreground: smartRuleHighlighterStyles.syntaxError },
    { token: 'at.ssmrule', foreground: smartRuleHighlighterStyles.syntaxAt },
    { token: 'every.ssmrule', foreground: smartRuleHighlighterStyles.syntaxEvery },
    { token: 'from.ssmrule', foreground: smartRuleHighlighterStyles.syntaxFrom },
    { token: 'to.ssmrule', foreground: smartRuleHighlighterStyles.syntaxTo },
    { token: 'now.ssmrule', foreground: smartRuleHighlighterStyles.syntaxNow },
    { token: 'timeintvalconst.ssmrule', foreground: smartRuleHighlighterStyles.syntaxTimeintvalconst },
    { token: 'long.ssmrule', foreground: smartRuleHighlighterStyles.syntaxLong },
  ],
});

export default MonacoCodeEditor;
