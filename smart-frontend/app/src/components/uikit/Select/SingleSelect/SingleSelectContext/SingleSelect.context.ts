import type { SelectOption, SingleSelectOptions } from '@uikit/Select/Select.types';
import type { ReactNode } from 'react';
import React, { useContext } from 'react';

export type SingleSelectContextOptions<T> = SingleSelectOptions<T> & {
  setOptions: (list: SelectOption<T>[]) => void;
  originalOptions: SelectOption<T>[];
  renderItem?: (model: SelectOption<T>) => ReactNode;
};

export const SingleSelectContext = React.createContext<SingleSelectContextOptions<unknown>>(
  {} as SingleSelectContextOptions<unknown>,
);

export const useSingleSelectContext = <T>() => {
  const ctx = useContext<SingleSelectContextOptions<T>>(
    SingleSelectContext as React.Context<SingleSelectContextOptions<T>>,
  );
  if (!ctx) {
    throw new Error('useContext must be inside a Provider with a value');
  }
  return ctx;
};
