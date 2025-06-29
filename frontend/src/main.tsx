import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import './App.css';

// Ensure dark mode is applied
document.documentElement.classList.add('dark');

// Get root element
const rootElement = document.getElementById('root');

// Ensure root element exists
if (!rootElement) {
  throw new Error('Root element not found');
}

// Create root and render app
const root = createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
