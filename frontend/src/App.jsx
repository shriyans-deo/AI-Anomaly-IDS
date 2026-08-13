import React, { useState, useEffect, useCallback } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import AnalyzeForm from './components/AnalyzeForm';
import ResultCard from './components/ResultCard';
import ThreatLog from './components/ThreatLog';
import ScoreChart from './components/ScoreChart';
import MatrixRain from './components/MatrixRain';
import './App.css';

const BACKEND_BASE_URL = 'http://127.0.0.1:8000';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [backendOnline, setBackendOnline] = useState(null);

  const handleLogin = () => setIsLoggedIn(true);
  const handleLogout = () => setIsLoggedIn(false);

  const handleResult = useCallback((data) => {
    setResult(data);
    setHistory((prev) => [
      {
        ...data,
        logId: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        loggedAt: new Date().toLocaleTimeString(),
      },
      ...prev,
    ]);
  }, []);

  // Poll backend health every 15s while logged in
  useEffect(() => {
    if (!isLoggedIn) return undefined;

    let cancelled = false;

    const checkHealth = async () => {
      try {
        const res = await fetch(BACKEND_BASE_URL, { method: 'GET' });
        if (!cancelled) setBackendOnline(res.ok);
      } catch {
        if (!cancelled) setBackendOnline(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 15000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isLoggedIn]);

  if (!isLoggedIn) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Dashboard onLogout={handleLogout} backendOnline={backendOnline}>
      <AnalyzeForm onResult={handleResult} />
      <ResultCard result={result} />
      <ScoreChart entries={history} />
      <ThreatLog entries={history} />
    </Dashboard>
  );
}

export default App;