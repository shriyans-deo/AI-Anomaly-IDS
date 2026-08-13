import React, { useState } from 'react';

function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!email.trim() || !password.trim()) {
      setError('ACCESS DENIED: Credentials required to authenticate.');
      return;
    }

    setError('');
    onLogin();
  };

  return (
    <div className="login-container">
      <div className="login-scanline"></div>
      <div className="login-card">
        <div className="login-header">
          <div className="login-icon">🛡</div>
          <h1 className="login-title">AI ANOMALY IDS</h1>
          <p className="login-subtitle">// Intrusion Detection System</p>
          <p className="login-tagline">Secure Access Terminal v2.1</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} noValidate>
          <div className="input-group">
            <label className="input-label" htmlFor="email">
              &gt; USER_ID / EMAIL
            </label>
            <input
              id="email"
              type="text"
              className="login-input"
              placeholder="operator@network.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="password">
              &gt; ACCESS_KEY
            </label>
            <div className="password-wrapper">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                className="login-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
              <button
                type="button"
                className="toggle-password-btn"
                onClick={() => setShowPassword((prev) => !prev)}
                tabIndex={-1}
              >
                {showPassword ? 'HIDE' : 'SHOW'}
              </button>
            </div>
          </div>

          {error && (
            <div className="login-error">
              <span className="login-error-icon">⚠</span>
              {error}
            </div>
          )}

          <button type="submit" className="login-button">
            <span className="login-button-text">AUTHENTICATE</span>
          </button>

          <div className="login-footer">
            <span className="status-dot"></span>
            System Status: Monitoring Active
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;