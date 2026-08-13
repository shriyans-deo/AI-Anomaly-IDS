import React from 'react';

const WIDTH = 600;
const HEIGHT = 200;
const PADDING = 30;

function ScoreChart({ entries }) {
  if (!entries || entries.length === 0) {
    return (
      <div className="chart-container">
        <h2 className="panel-title">// Anomaly Score Trend</h2>
        <p className="result-empty-text">
          &gt; No data yet. Run an analysis to see the trend.
        </p>
      </div>
    );
  }

  const chronological = [...entries].reverse();
  const maxScore = Math.max(100, ...chronological.map((e) => e.anomaly_score || 0));
  const usableWidth = WIDTH - PADDING * 2;
  const usableHeight = HEIGHT - PADDING * 2;

  const points = chronological.map((entry, index) => {
    const x =
      chronological.length === 1
        ? PADDING
        : PADDING + (index / (chronological.length - 1)) * usableWidth;
    const y =
      PADDING + usableHeight - (entry.anomaly_score / maxScore) * usableHeight;
    return { x, y, entry };
  });

  const linePath = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(' ');

  const gridLines = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="chart-container">
      <h2 className="panel-title">// Anomaly Score Trend</h2>

      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="score-chart-svg"
        preserveAspectRatio="xMidYMid meet"
      >
        {gridLines.map((g) => {
          const y = PADDING + usableHeight * g;
          return (
            <line
              key={g}
              x1={PADDING}
              y1={y}
              x2={WIDTH - PADDING}
              y2={y}
              className="chart-grid-line"
            />
          );
        })}

        <path d={linePath} className="chart-line" fill="none" />

        {points.map((p, i) => {
          const isNormal =
            p.entry.ml_flagged === false && p.entry.severity === 'none';
          return (
            <circle
              key={i}
              cx={p.x}
              cy={p.y}
              r={4}
              className={
                isNormal ? 'chart-point chart-point-normal' : 'chart-point chart-point-anomaly'
              }
            >
              <title>
                {`${p.entry.src_ip} - score ${p.entry.anomaly_score} (${p.entry.severity})`}
              </title>
            </circle>
          );
        })}
      </svg>

      <div className="chart-legend">
        <span className="chart-legend-item">
          <span className="chart-legend-dot chart-legend-dot-normal"></span> Normal
        </span>
        <span className="chart-legend-item">
          <span className="chart-legend-dot chart-legend-dot-anomaly"></span> Anomaly
        </span>
      </div>
    </div>
  );
}

export default ScoreChart;