import React, { useState } from 'react';

const API_URL = 'http://127.0.0.1:8000/analyze';

const initialFormState = {
  timestamp: '2026-08-07T09:00:00',
  src_ip: '10.0.0.4',
  num_connections: 6,
  unique_dst_ports: 3,
  bytes_sent: 5759.9,
  bytes_recv: 17941.8,
  failed_logins: 0,
  syn_ratio: 0.168,
  avg_conn_duration: 9.81,
  label: 'normal',
};

function AnalyzeForm({ onResult }) {
  const [formData, setFormData] = useState(initialFormState);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const numericFields = [
    'num_connections',
    'unique_dst_ports',
    'bytes_sent',
    'bytes_recv',
    'failed_logins',
    'syn_ratio',
    'avg_conn_duration',
  ];

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((prev) => ({
      ...prev,
      [name]: numericFields.includes(name) ? value : value,
    }));
  };

  const buildPayload = () => {
    const payload = { ...formData };

    numericFields.forEach((field) => {
      const parsed = parseFloat(payload[field]);
      payload[field] = isNaN(parsed) ? 0 : parsed;
    });

    return payload;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const payload = buildPayload();

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        let detail = '';
        try {
          const errBody = await response.json();
          detail = errBody?.detail
            ? typeof errBody.detail === 'string'
              ? errBody.detail
              : JSON.stringify(errBody.detail)
            : '';
        } catch {
          // response body wasn't JSON, ignore
        }
        throw new Error(
          `Request failed (${response.status} ${response.statusText})${
            detail ? `: ${detail}` : ''
          }`
        );
      }

      const data = await response.json();
      onResult(data);
    } catch (err) {
      if (err instanceof TypeError) {
        setError(
          'CONNECTION FAILED: Unable to reach analysis engine at 127.0.0.1:8000. Is the backend running?'
        );
      } else {
        setError(`ANALYSIS ERROR: ${err.message}`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="analyze-form-container">
      <div className="analyze-form-header">
        <h2 className="analyze-form-title">// Traffic Analysis Input</h2>
        <p className="analyze-form-subtitle">
          Submit network flow parameters for anomaly detection
        </p>
      </div>

      <form className="analyze-form" onSubmit={handleSubmit}>
        <div className="analyze-form-grid">
          <div className="input-group">
            <label className="input-label" htmlFor="timestamp">
              &gt; TIMESTAMP
            </label>
            <input
              id="timestamp"
              name="timestamp"
              type="text"
              className="login-input"
              value={formData.timestamp}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="src_ip">
              &gt; SOURCE IP
            </label>
            <input
              id="src_ip"
              name="src_ip"
              type="text"
              className="login-input"
              value={formData.src_ip}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="num_connections">
              &gt; NUM CONNECTIONS
            </label>
            <input
              id="num_connections"
              name="num_connections"
              type="number"
              step="1"
              className="login-input"
              value={formData.num_connections}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="unique_dst_ports">
              &gt; UNIQUE DST PORTS
            </label>
            <input
              id="unique_dst_ports"
              name="unique_dst_ports"
              type="number"
              step="1"
              className="login-input"
              value={formData.unique_dst_ports}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="bytes_sent">
              &gt; BYTES SENT
            </label>
            <input
              id="bytes_sent"
              name="bytes_sent"
              type="number"
              step="any"
              className="login-input"
              value={formData.bytes_sent}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="bytes_recv">
              &gt; BYTES RECEIVED
            </label>
            <input
              id="bytes_recv"
              name="bytes_recv"
              type="number"
              step="any"
              className="login-input"
              value={formData.bytes_recv}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="failed_logins">
              &gt; FAILED LOGINS
            </label>
            <input
              id="failed_logins"
              name="failed_logins"
              type="number"
              step="1"
              className="login-input"
              value={formData.failed_logins}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="syn_ratio">
              &gt; SYN RATIO
            </label>
            <input
              id="syn_ratio"
              name="syn_ratio"
              type="number"
              step="any"
              className="login-input"
              value={formData.syn_ratio}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="avg_conn_duration">
              &gt; AVG CONN DURATION
            </label>
            <input
              id="avg_conn_duration"
              name="avg_conn_duration"
              type="number"
              step="any"
              className="login-input"
              value={formData.avg_conn_duration}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="label">
              &gt; LABEL
            </label>
            <input
              id="label"
              name="label"
              type="text"
              className="login-input"
              value={formData.label}
              onChange={handleChange}
            />
          </div>
        </div>

        {error && (
          <div className="login-error">
            <span className="login-error-icon">⚠</span>
            {error}
          </div>
        )}

        <button
          type="submit"
          className="login-button analyze-button"
          disabled={isLoading}
        >
          {isLoading ? 'ANALYZING...' : 'ANALYZE TRAFFIC'}
        </button>
      </form>
    </div>
  );
}

export default AnalyzeForm;