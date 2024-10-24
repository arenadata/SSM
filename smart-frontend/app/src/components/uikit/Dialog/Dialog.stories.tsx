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
import type { Meta, StoryObj } from '@storybook/react';
import Button from '@uikit/Button/Button';
import React, { useEffect, useRef, useState } from 'react';
import type { DialogProps } from './Dialog';
import Dialog from './Dialog';
import s from '@uikit/Dialog/Dialog.module.scss';
import Popover from '@uikit/Popover/Popover';
import ButtonGroup from '@uikit/ButtonGroup/ButtonGroup';

type Story = StoryObj<typeof Dialog>;
export default {
  title: 'uikit/Dialog',
  component: Dialog,
  argTypes: {
    onOpenChange: {
      table: {
        disable: true,
      },
    },
    isPrimaryOpen: {
      table: {
        disable: true,
      },
    },
    dialogFooter: {
      table: {
        disable: true,
      },
    },
  },
} as Meta<typeof Dialog>;

const EasyDialogExample: React.FC<DialogProps> = (props) => {
  const [isOpen, setIsOpen] = useState(false);
  const handleAction = () => {
    props.onAction?.();
    setIsOpen(false);
  };
  return (
    <>
      <Button onClick={() => setIsOpen((prev) => !prev)}>Click to open dialog</Button>
      <Dialog {...props} isOpen={isOpen} onOpenChange={setIsOpen} onAction={handleAction}>
        <div>
          Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam commodo dui vel turpis mollis dignissim.
          Aliquam semper risus sollicitudin, consectetur risus aliquam, fringilla neque. Sed cursus elit eu sem bibendum
          euismod sit amet in erat. Sed id congue libero. Maecenas in commodo nisl, et eleifend lacus. Ut convallis eros
          eget justo sollicitudin pulvinar. Sed eu tellus quis erat auctor tincidunt sit amet eu augue. In fermentum
          egestas mauris vitae porttitor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla facilisi. Sed
          odio nunc, feugiat vel finibus dapibus, molestie a ipsum. Aenean scelerisque eget ipsum eget luctus.
        </div>
      </Dialog>
    </>
  );
};
export const EasyDialog: Story = {
  args: {
    title: 'Lorem ipsum',
    width: '584px',
  },
  render: (args) => {
    return <EasyDialogExample {...args} />;
  },
};

const CustomControlsDialogExample: React.FC<DialogProps> = ({ onAction, onCancel, ...props }) => {
  const [isPrimaryOpen, setIsPrimaryOpen] = useState(false);
  const [isActionDisabled, setIsActionDisabled] = useState(true);
  const [isPrimaryDialogCloseDisabled, setIsPrimaryDialogCloseDisabled] = useState(false);

  const [isSecondaryOpen, setIsSecondaryOpen] = useState(false);

  useEffect(() => {
    setIsActionDisabled(false);
  }, [isPrimaryOpen]);
  const handlePrimaryAction = () => {
    onAction?.();
    setIsSecondaryOpen(true);
    setIsPrimaryDialogCloseDisabled(true);
  };
  const handlePrimaryCancel = () => {
    onCancel?.();
    setIsPrimaryOpen(false);
  };
  const handleSecondaryAction = () => {
    setIsSecondaryOpen(false);
    setIsPrimaryOpen(false);
  };
  const handleSecondaryCancel = () => {
    setIsPrimaryDialogCloseDisabled(false);
  };
  const dialogControls = (
    <ButtonGroup className={s.dialog__defaultControls}>
      <Button variant="secondary" onClick={handlePrimaryCancel}>
        Cancel
      </Button>
      <Button disabled={isActionDisabled} onClick={handlePrimaryAction}>
        OK
      </Button>
    </ButtonGroup>
  );

  return (
    <>
      <Button onClick={() => setIsPrimaryOpen((prev) => !prev)}>Click to open dialog</Button>
      <Dialog
        {...props}
        isOpen={isPrimaryOpen}
        onOpenChange={setIsPrimaryOpen}
        dialogControls={dialogControls}
        isDismissDisabled={isPrimaryDialogCloseDisabled}
      >
        <div>
          Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam commodo dui vel turpis mollis dignissim.
          Aliquam semper risus sollicitudin, consectetur risus aliquam, fringilla neque. Sed cursus elit eu sem bibendum
          euismod sit amet in erat. Sed id congue libero. Maecenas in commodo nisl, et eleifend lacus. Ut convallis eros
          eget justo sollicitudin pulvinar. Sed eu tellus quis erat auctor tincidunt sit amet eu augue. In fermentum
          egestas mauris vitae porttitor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla facilisi. Sed
          odio nunc, feugiat vel finibus dapibus, molestie a ipsum. Aenean scelerisque eget ipsum eget luctus.
        </div>
      </Dialog>
      <Dialog
        isOpen={isSecondaryOpen}
        onOpenChange={setIsSecondaryOpen}
        onCancel={handleSecondaryCancel}
        isDismissDisabled={true}
        dialogControls={
          <div style={{ display: 'flex', justifyContent: 'right' }}>
            <Button onClick={handleSecondaryAction}>Okay</Button>
          </div>
        }
      >
        You may close the dialog now!
      </Dialog>
    </>
  );
};
export const CustomControlsDialog: Story = {
  args: {
    title: 'Lorem ipsum',
    width: '864px',
  },
  render: (args) => {
    return <CustomControlsDialogExample {...args} />;
  },
};

const DialogWithPopoverChildExample: React.FC<DialogProps> = ({ title, width }) => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isPopoverOpen, setIsPopoverOpen] = useState(false);
  const localRef = useRef(null);

  return (
    <div>
      <Button onClick={() => setIsDialogOpen((prev) => !prev)}>Click to open dialog with Popover Child</Button>
      <Dialog
        title={title}
        width={width}
        isOpen={isDialogOpen}
        onOpenChange={setIsDialogOpen}
        onAction={() => {
          setIsDialogOpen(false);
        }}
      >
        <div>
          <Button
            ref={localRef}
            onClick={() => {
              setIsPopoverOpen((prev) => !prev);
            }}
            style={{ margin: 'auto' }}
          >
            Click to show popover
          </Button>
          <Popover isOpen={isPopoverOpen} onOpenChange={setIsPopoverOpen} triggerRef={localRef}>
            <div style={{ background: 'green', color: '#000', fontSize: '30px', minHeight: '100px' }}>
              Show Popup content
            </div>
          </Popover>
        </div>
      </Dialog>
    </div>
  );
};

export const DialogWithPopoverChild: Story = {
  args: {
    title: 'Try to open Popover in Dialog',
    width: '864px',
  },
  render: (args) => {
    return <DialogWithPopoverChildExample {...args} />;
  },
};
