import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, theme } from 'antd';
import App from './App';
import 'antd/dist/reset.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#0a66ff',
          colorInfo: '#0a66ff',
          fontFamily: '"SF Pro Display", "SF Pro Text", "Manrope", "Noto Sans SC", "Helvetica Neue", Arial, sans-serif',
          borderRadius: 12,
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>
);
