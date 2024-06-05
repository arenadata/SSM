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
import React, { useRef } from 'react';
import cn from 'classnames';
import type { InputProps } from '@uikit/Input/Input';
import Input from '@uikit/Input/Input';
import { useForwardRef } from '@hooks/useForwardRef';
import { createChangeEvent } from '@utils/handlerUtils';
import IconButton from '@uikit/IconButton/IconButton';

const SearchInput = React.forwardRef<HTMLInputElement, InputProps>(({ className, ...props }, ref) => {
  const localRef = useRef<HTMLInputElement>(null);
  const reference = useForwardRef(ref, localRef);

  const handleIconClick = () => {
    if (props.value && localRef.current) {
      const event = createChangeEvent(localRef.current);
      event.target.value = '';
      props.onChange?.(event);
    }
  };

  return (
    <Input
      {...props}
      className={cn(className, 'search-input')}
      ref={reference}
      endAdornment={
        <IconButton icon={props.value ? 'close' : 'search'} onClick={handleIconClick} size={12} variant="secondary" />
      }
      size="medium"
    />
  );
});

SearchInput.displayName = 'SearchInput';
export default SearchInput;