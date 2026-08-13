import React from 'react';

function ResultCard({ result }) {
  if (!result) {
    return (
      <div className="result-card result-card-empty">
        <p className="result-empty-text">
          &gt; No analysis yet. Submit traffic data to detect anomalies.
        </p>
      </div>
    );
  }

  const {
    src_ip,
    label,
    anomaly_score,
    ml_flagged,
    rules_triggered,
    severity,
  } = result;

  const isNormal = ml_flagged === false && severity === 'none';
  const statusClass = isNormal ? 'result-status-normal' : 'result-status-anomaly';
  const cardClass = isNormal
    ? 'result-card result-card-normal'
    : 'result-card result-card-anomaly';

  const rulesList =
    Array.isArray(rules_triggered) && rules_triggered.length > 0
      ? rules_triggered
      : [];

  return (
    <div className={cardClass}>
      <div className={`result-status-banner ${statusClass}`}>
        {isNormal ? 'NORMAL TRAFFIC' : 'ANOMALY DETECTED'}
      </div>

      <div className="result-details">
        <div className="result-row">
          <span className="result-label">&gt; SOURCE IP</span>
          <span className="result-value">{src_ip ?? 'N/A'}</span>
        </div>

        <div className="result-row">
          <span className="result-label">&gt; TRAFFIC LABEL</span>
          <span className="result-value">{label ?? 'N/A'}</span>
        </div>

        <div className="result-row">
          <span className="result-label">&gt; ANOMALY SCORE</span>
          <span className="result-value">{anomaly_score ?? 'N/A'}</span>
        </div>

        <div className="result-row">
          <span className="result-label">&gt; ML FLAGGED</span>
          <span className="result-value">
            {ml_flagged ? 'TRUE' : 'FALSE'}
          </span>
        </div>

        <div className="result-row">
          <span className="result-label">&gt; SEVERITY</span>
          <span className="result-value">{severity ?? 'N/A'}</span>
        </div>

        <div className="result-row result-row-rules">
          <span className="result-label">&gt; RULES TRIGGERED</span>
          {rulesList.length > 0 ? (
            <ul className="result-rules-list">
              {rulesList.map((rule, index) => (
                <li key={index} className="result-rule-item">
                  {rule}
                </li>
              ))}
            </ul>
          ) : (
            <span className="result-value">None</span>
          )}
        </div>
      </div>
    </div>
  );
}

export default ResultCard;