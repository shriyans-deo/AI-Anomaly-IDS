import React, { useState, useEffect } from 'react';
import MatrixRain from './MatrixRain';

const FULL_TITLE = 'AI Anomaly IDS';

function Dashboard({ onLogout, backendOnline, children }) {
  const [typedTitle, setTypedTitle] = useState('');

  useEffect(() => {
    let index = 0;
    setTypedTitle('');

    const interval = setInterval(() => {
      index += 1;
      setTypedTitle(FULL_TITLE.slice(0, index));

      if (index >= FULL_TITLE.length) {
        clearInterval(interval);
      }
    }, 80);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      <MatrixRain />
      <div className="dashboard-scanline"></div>

      <header className="dashboard-header">
        <div className="dashboard-header-left">
          <div className="dashboard-icon">🛡</div>
          <div className="dashboard-titles">
            <h1 className="dashboard-title">
              {typedTitle}
              <span className="typewriter-cursor">_</span>
            </h1>
            <p className="dashboard-subtitle">
              AI-powered anomaly-based Intrusion Detection System
            </p>
          </div>
        </div>

        <div className="dashboard-header-right">
          <div className="dashboard-status">
            <span
              className={`status-dot ${
                backendOnline === false ? 'status-dot-offline' : ''
              }`}
            ></span>
            <span className="dashboard-status-text">
              {backendOnline === false
                ? 'BACKEND OFFLINE'
                : backendOnline === true
                ? 'MONITORING ACTIVE'
                : 'CHECKING STATUS...'}
            </span>
          </div>
          <button type="button" className="logout-button" onClick={onLogout}>
            LOGOUT
          </button>
        </div>
      </header>

      <main className="dashboard-content">{children}</main>
    </div>
  );
}

export default Dashboard;