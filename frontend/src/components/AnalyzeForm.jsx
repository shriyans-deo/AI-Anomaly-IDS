import React, { useCallback, useEffect, useRef, useState } from 'react';

const API_BASE_URL = 'http://127.0.0.1:8000';
const LIVE_ANALYZE_URL = `${API_BASE_URL}/analyze/live`;


const CAPTURE_WINDOW_SECONDS = 10;
const REQUEST_TIMEOUT_MS = (CAPTURE_WINDOW_SECONDS + 15) * 1000;

const CYCLE_GAP_MS = 400;

const RETRY_DELAY_MS = 5000;


const IDLE_FLOW = {
  timestamp: '—',
  src_ip: '—',
  num_connections: 0,
  unique_dst_ports: 0,
  bytes_sent: 0,
  bytes_recv: 0,
  failed_logins: 0,
  syn_ratio: 0,
  avg_conn_duration: 0,
  label: '—',
};

const NUMERIC_FIELDS = [
  'num_connections',
  'unique_dst_ports',
  'bytes_sent',
  'bytes_recv',
  'failed_logins',
  'syn_ratio',
  'avg_conn_duration',
];


const TELEMETRY_GROUPS = [
  {
    title: '// Connection Metrics',
    fields: [
      { name: 'num_connections', label: 'NUM CONNECTIONS' },
      { name: 'unique_dst_ports', label: 'UNIQUE DST PORTS' },
      { name: 'avg_conn_duration', label: 'AVG CONN DURATION (s)' },
    ],
  },
  {
    title: '// Traffic Volume',
    fields: [
      { name: 'bytes_sent', label: 'BYTES SENT' },
      { name: 'bytes_recv', label: 'BYTES RECEIVED' },
    ],
  },
  {
    title: '// Security Indicators',
    fields: [
      { name: 'failed_logins', label: 'FAILED LOGINS' },
      { name: 'syn_ratio', label: 'SYN RATIO' },
    ],
  },
];

const IPV4_REGEX =
  /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;

const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

function isValidIp(value) {
  return IPV4_REGEX.test(value) || IPV6_REGEX.test(value);
}

function isInteger(value) {
  return Number.isInteger(value);
}


function normalizeFlow(raw) {
  const flow = { ...raw };

  NUMERIC_FIELDS.forEach((field) => {
    const parsed = parseFloat(flow[field]);
    flow[field] = isNaN(parsed) ? 0 : parsed;
  });

  return flow;
}


function validateFlow(payload) {
  if (!payload.src_ip || !isValidIp(String(payload.src_ip).trim())) {
    return 'VALIDATION ERROR: src_ip must be a valid IPv4 or IPv6 address.';
  }

  if (payload.label !== 'normal' && payload.label !== 'attack') {
    return 'VALIDATION ERROR: label must be either "normal" or "attack".';
  }

  if (isNaN(payload.num_connections) || payload.num_connections < 0) {
    return 'VALIDATION ERROR: num_connections must be >= 0.';
  }
  if (!isInteger(payload.num_connections)) {
    return 'VALIDATION ERROR: num_connections must be an integer.';
  }

  if (isNaN(payload.unique_dst_ports) || payload.unique_dst_ports < 0) {
    return 'VALIDATION ERROR: unique_dst_ports must be >= 0.';
  }
  if (payload.unique_dst_ports > 65535) {
    return 'VALIDATION ERROR: unique_dst_ports must be <= 65535.';
  }
  if (!isInteger(payload.unique_dst_ports)) {
    return 'VALIDATION ERROR: unique_dst_ports must be an integer.';
  }

  if (isNaN(payload.bytes_sent) || payload.bytes_sent < 0) {
    return 'VALIDATION ERROR: bytes_sent must be >= 0.';
  }

  if (isNaN(payload.bytes_recv) || payload.bytes_recv < 0) {
    return 'VALIDATION ERROR: bytes_recv must be >= 0.';
  }

  if (isNaN(payload.failed_logins) || payload.failed_logins < 0) {
    return 'VALIDATION ERROR: failed_logins must be >= 0.';
  }
  if (!isInteger(payload.failed_logins)) {
    return 'VALIDATION ERROR: failed_logins must be an integer.';
  }

  if (isNaN(payload.syn_ratio) || payload.syn_ratio < 0) {
    return 'VALIDATION ERROR: syn_ratio must be >= 0.';
  }
  if (payload.syn_ratio > 1) {
    return 'VALIDATION ERROR: syn_ratio must be <= 1.';
  }

  if (isNaN(payload.avg_conn_duration) || payload.avg_conn_duration < 0) {
    return 'VALIDATION ERROR: avg_conn_duration must be >= 0.';
  }

  return '';
}


const READONLY_FIELD_STYLE = {
  caretColor: 'transparent',
  cursor: 'default',
  pointerEvents: 'none',
  outline: 'none',
  boxShadow: 'none',
  userSelect: 'none',
};

function formatValue(value) {
  if (value === null || value === undefined || value === '') return '—';
  return String(value);
}

function TelemetryReadout({ name, label, value, extraClassName = '' }) {
  return (
    <input
      id={name}
      name={name}
      type="text"
      readOnly
      disabled
      tabIndex={-1}
      aria-readonly="true"
      className={`login-input telemetry-readonly ${extraClassName}`.trim()}
      style={READONLY_FIELD_STYLE}
      value={formatValue(value)}
      aria-label={label}
      onChange={() => {}}
    />
  );
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function AnalyzeForm({ onResult, iface, autoStart = true }) {
  const [flow, setFlow] = useState(IDLE_FLOW);
  const [isMonitoring, setIsMonitoring] = useState(autoStart);
  const [isCapturing, setIsCapturing] = useState(false);
  const [cycleCount, setCycleCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState('');
  const [error, setError] = useState('');

 
  const activeControllerRef = useRef(null);

  const buildLiveUrl = useCallback(() => {
    const params = new URLSearchParams({ window: String(CAPTURE_WINDOW_SECONDS) });
    if (iface) params.set('iface', iface);
    return `${LIVE_ANALYZE_URL}?${params.toString()}`;
  }, [iface]);


  useEffect(() => {
    if (!isMonitoring) return undefined;

    let cancelled = false;

    const runOneCycle = async () => {
      const controller = new AbortController();
      activeControllerRef.current = controller;
      const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      try {
        // /analyze/live takes window/iface as query params and no request body.
        const response = await fetch(buildLiveUrl(), {
          method: 'POST',
          signal: controller.signal,
        });

        if (cancelled) return true;

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
            e
          }

          if (response.status === 404) {
            
            setError(
              `NO TRAFFIC IN LAST WINDOW: ${
                detail || 'No traffic observed.'
              } Sensor still active.`
            );
            return true;
          }

          throw new Error(
            `Request failed (${response.status} ${response.statusText})${
              detail ? `: ${detail}` : ''
            }`
          );
        }

        const data = await response.json();
        if (cancelled) return true;

        if (!data || !data.flow) {
          throw new Error('Malformed response from /analyze/live: missing "flow".');
        }

        const liveFlow = normalizeFlow(data.flow);
        setFlow(liveFlow);
        onResult(data.result);
        setCycleCount((n) => n + 1);
        setLastUpdate(new Date().toLocaleTimeString());
        setError(validateFlow(liveFlow));
        return true;
      } catch (err) {
        if (cancelled || err.name === 'AbortError') {
          
          if (!cancelled) {
            setError(
              `CAPTURE TIMEOUT: No response within ${
                REQUEST_TIMEOUT_MS / 1000
              }s. Retrying — check backend capture privileges.`
            );
          }
          return false;
        }
        if (err instanceof TypeError) {
          setError(
            'CONNECTION FAILED: Unable to reach analysis engine at 127.0.0.1:8000. Retrying...'
          );
        } else {
          setError(`ANALYSIS ERROR: ${err.message} — retrying.`);
        }
        return false;
      } finally {
        clearTimeout(timeoutId);
        if (activeControllerRef.current === controller) {
          activeControllerRef.current = null;
        }
      }
    };

    const loop = async () => {
      while (!cancelled) {
        setIsCapturing(true);
        const ok = await runOneCycle();
        if (cancelled) return;
        setIsCapturing(false);

        
        await sleep(ok ? CYCLE_GAP_MS : RETRY_DELAY_MS);
      }
    };

    loop();

    return () => {
      cancelled = true;
      if (activeControllerRef.current) {
        activeControllerRef.current.abort();
        activeControllerRef.current = null;
      }
    };
  }, [isMonitoring, buildLiveUrl, onResult]);

 
  useEffect(() => {
    if (!isMonitoring) setIsCapturing(false);
  }, [isMonitoring]);

  const toggleMonitoring = () => {
    setError('');
    setIsMonitoring((on) => !on);
  };

  const statusColor = isMonitoring ? '#39ff6a' : '#8a8f8a';
  const statusText = isMonitoring
    ? isCapturing
      ? `CAPTURING (${CAPTURE_WINDOW_SECONDS}s window)`
      : 'PROCESSING'
    : 'STOPPED';

  return (
    <div className="analyze-form-container">
      <div className="analyze-form-header">
        <h2 className="analyze-form-title">// Live Traffic Features</h2>
        <p className="analyze-form-subtitle">
          Network-flow features extracted for anomaly detection
        </p>
      </div>

      <form className="analyze-form" onSubmit={(e) => e.preventDefault()}>
        {/* Sensor status - replaces the manual analyze trigger */}
        <div className="telemetry-group">
          <h3 className="telemetry-group-title">// Sensor Status</h3>
          <div className="telemetry-grid">
            <div className="telemetry-field">
              <span className="telemetry-micro-label">MONITORING</span>
              <span
                className="telemetry-micro-label"
                style={{ color: statusColor, fontSize: '1rem', letterSpacing: '0.05em' }}
              >
                ● {isMonitoring ? 'LIVE MONITORING' : 'MONITORING STOPPED'}
              </span>
            </div>

            <div className="telemetry-field">
              <span className="telemetry-micro-label">SENSOR</span>
              <span className="telemetry-micro-label" style={{ color: statusColor }}>
                {statusText}
              </span>
            </div>

            <div className="telemetry-field">
              <span className="telemetry-micro-label">CYCLES / LAST UPDATE</span>
              <span className="telemetry-micro-label">
                {cycleCount} {lastUpdate ? `· ${lastUpdate}` : ''}
              </span>
            </div>
          </div>
        </div>

        {/* Identity / origin block - source IP is the headline field */}
        <div className="telemetry-identity-block">
          <div className="telemetry-src-ip-group">
            <span className="telemetry-micro-label">&gt; SOURCE IP</span>
            <TelemetryReadout
              name="src_ip"
              label="SOURCE IP"
              value={flow.src_ip}
              extraClassName="telemetry-src-ip-input"
            />
          </div>

          <div className="telemetry-identity-meta">
            <div className="telemetry-field-inline">
              <span className="telemetry-micro-label">&gt; TIMESTAMP</span>
              <TelemetryReadout
                name="timestamp"
                label="TIMESTAMP"
                value={flow.timestamp}
                extraClassName="telemetry-meta-input"
              />
            </div>

            <div className="telemetry-field-inline">
              <span className="telemetry-micro-label">&gt; LABEL</span>
              <TelemetryReadout
                name="label"
                label="LABEL"
                value={flow.label}
                extraClassName="telemetry-meta-input"
              />
            </div>
          </div>
        </div>

        {/* Telemetry groups - read-only, driven by TELEMETRY_GROUPS */}
        {TELEMETRY_GROUPS.map((group) => (
          <div className="telemetry-group" key={group.title}>
            <h3 className="telemetry-group-title">{group.title}</h3>
            <div className="telemetry-grid">
              {group.fields.map((field) => (
                <div className="telemetry-field" key={field.name}>
                  <span className="telemetry-micro-label">{field.label}</span>
                  <TelemetryReadout
                    name={field.name}
                    label={field.label}
                    value={flow[field.name]}
                    extraClassName="telemetry-value-input"
                  />
                </div>
              ))}
            </div>
          </div>
        ))}

        {error && (
          <div className="login-error">
            <span className="login-error-icon">⚠</span>
            {error}
          </div>
        )}

        <button
          type="button"
          className="login-button analyze-button"
          onClick={toggleMonitoring}
        >
          {isMonitoring ? 'STOP MONITORING' : 'START MONITORING'}
        </button>
      </form>
    </div>
  );
}

export default AnalyzeForm;