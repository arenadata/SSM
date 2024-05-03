import React, { useState } from 'react';
import type { OffsetOptions } from '@floating-ui/react';
import {
  autoUpdate,
  flip,
  offset,
  shift,
  useDismiss,
  useFloating,
  useFocus,
  useHover,
  useClick,
  useInteractions,
  useRole,
  FloatingPortal,
  useDelayGroup,
} from '@floating-ui/react';
import type { Placement } from '@floating-ui/dom';
import { useForwardRef } from '@hooks/useForwardRef';
import type { ChildWithRef } from '@uikit/types/element.types';
import cn from 'classnames';
import s from './Tooltip.module.scss';

export interface TooltipProps {
  label: React.ReactNode;
  placement?: Placement;
  offset?: OffsetOptions;
  children: ChildWithRef;
  className?: string;
  closeDelay?: number;
  dataTest?: string;
}

const Tooltip: React.FC<TooltipProps> = ({
  children,
  label,
  className,
  placement = 'top' as Placement,
  offset: offsetValue = 10,
  closeDelay = 0,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const { refs, floatingStyles, context } = useFloating({
    open: isOpen,
    onOpenChange: setIsOpen,
    placement,
    // Make sure the tooltip stays on the screen
    whileElementsMounted: autoUpdate,
    middleware: [
      offset(offsetValue),
      flip({
        fallbackAxisSideDirection: 'start',
      }),
      shift({ padding: 8 }),
    ],
  });

  const { delay } = useDelayGroup(context, {
    id: context.floatingId,
  });

  const hover = useHover(context, {
    move: false,
    delay: closeDelay
      ? {
          open: 0,
          close: closeDelay,
        }
      : delay,
  });
  const click = useClick(context);
  const focus = useFocus(context);
  const dismiss = useDismiss(context);
  // Role props for screen readers
  const role = useRole(context, { role: 'tooltip' });

  const { getReferenceProps, getFloatingProps } = useInteractions([hover, focus, click, dismiss, role]);

  const ref = useForwardRef(refs.setReference, children.ref);

  const targetElement = React.Children.only(children);

  return (
    <>
      {React.cloneElement(targetElement, getReferenceProps({ ref, ...children.props }))}
      <FloatingPortal>
        {isOpen && (
          <div
            ref={refs.setFloating}
            className={cn(s.tooltip, className)}
            style={floatingStyles}
            {...getFloatingProps()}
          >
            {label}
          </div>
        )}
      </FloatingPortal>
    </>
  );
};
export default Tooltip;