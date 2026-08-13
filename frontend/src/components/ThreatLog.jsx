import React from 'react';

function ThreatLog({ entries }) {
  if (!entries || entries.length === 0) {
    return (
      <div className="threat-log-container">
        <h2 className="panel-title">// Threat Log</h2>
        <p className="result-empty-text">
          &gt; No events logged yet. Run an analysis to populate the log.
        </p>
      </div>
    );
  }

  return (
    <div className="threat-log-container">
      <h2 className="panel-title">
        // Threat Log <span className="panel-title-count">({entries.length})</span>
      </h2>

      <div className="threat-log-list">
        {entries.map((entry) => {
          const isNormal = entry.ml_flagged === false && entry.severity === 'none';
          return (
            <div
              key={entry.logId}
              className={`threat-log-row ${
                isNormal ? 'threat-log-row-normal' : 'threat-log-row-anomaly'
              }`}
            >
              <span className="threat-log-time">{entry.loggedAt}</span>
              <span className="threat-log-ip">{entry.src_ip}</span>
              <span className="threat-log-score">
                score: {entry.anomaly_score}
              </span>
              <span className="threat-log-badge">
                {isNormal ? 'NORMAL' : entry.severity?.toUpperCase() || 'ANOMALY'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default ThreatLog;