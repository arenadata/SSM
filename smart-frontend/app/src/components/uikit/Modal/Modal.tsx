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
import type { CSSProperties } from 'react';
import React from 'react';
import type { ModalOptions } from './Modal.types';
import {
  FloatingFocusManager,
  FloatingOverlay,
  FloatingPortal,
  useDismiss,
  useFloating,
  useInteractions,
  useRole,
} from '@floating-ui/react';
import s from './Modal.module.scss';
import cn from 'classnames';

interface ModalProps extends ModalOptions {
  children: React.ReactNode;
  className?: string;
  style?: CSSProperties;
  dataTest?: string;
}

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onOpenChange,
  isDismissDisabled = false,
  className,
  style,
  children,
  dataTest = 'modal-container',
}) => {
  const { refs, context } = useFloating({
    open: isOpen,
    onOpenChange: onOpenChange,
  });

  const role = useRole(context);
  const dismiss = useDismiss(context, { enabled: !isDismissDisabled });

  const { getFloatingProps } = useInteractions([role, dismiss]);

  return (
    <FloatingPortal>
      {isOpen && (
        <FloatingOverlay className={s.modalOverlay} lockScroll>
          <FloatingFocusManager context={context}>
            <div
              ref={refs.setFloating}
              {...getFloatingProps()}
              className={cn(s.modal, className)}
              style={style}
              data-qa={dataTest}
            >
              {children}
            </div>
          </FloatingFocusManager>
        </FloatingOverlay>
      )}
    </FloatingPortal>
  );
};
export default Modal;
