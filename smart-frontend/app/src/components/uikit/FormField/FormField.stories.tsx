import type { Meta, StoryObj } from '@storybook/react';
import FormField from '@uikit/FormField/FormField';
import React, { useState } from 'react';
import Input from '@uikit/Input/Input';
import Button from '@uikit/Button/Button';
import FormFieldsContainer from '@uikit/FormField/FormFieldsContainer';

type Story = StoryObj<typeof FormField>;
export default {
  title: 'uikit/Forms',
  component: FormField,
} as Meta<typeof FormField>;

const FormsEasyComponent: React.FC = () => {
  const [username, setUsername] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);

  const hasError = !!errorMessage;

  const handleUsernameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setErrorMessage(undefined);
    setUsername(event.target.value);
  };

  const handleSubmit = (event: React.SyntheticEvent) => {
    event.preventDefault();

    if (username !== 'admin') {
      setErrorMessage('Wrong credentials data');
    } else {
      alert('Congratulations!');
    }
  };

  return (
    <form onSubmit={handleSubmit} autoComplete="off" style={{ padding: '100px 0' }}>
      <FormFieldsContainer>
        <FormField label="User" error={errorMessage} hint="The username is 'admin'.">
          <Input
            value={username}
            type="text"
            name="username"
            onChange={handleUsernameChange}
            placeholder="Enter username"
            autoComplete="username"
          />
        </FormField>
        <Button type="submit" hasError={hasError} disabled={hasError} style={{ width: '100%' }}>
          Sign in
        </Button>
      </FormFieldsContainer>
    </form>
  );
};

export const Forms: Story = {
  render: () => {
    return (
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <FormsEasyComponent />
      </div>
    );
  },
};
