import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const Dashboard = () => {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    totalAlerts: 0,
    blockedAlerts: 0,
    protocols: {},
  });

  // In the Docker/Kubernetes deployment Nginx proxies /api to the Commander.
  // A full URL can be supplied for local `npm start` development.
  const API_BASE_URL = process.env.REACT_APP_API_URL || '';

  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const [alertsResponse, summaryResponse] = await Promise.all([
          axios.get(`${API_BASE_URL}/api/v1/alerts?limit=100`),
          axios.get(`${API_BASE_URL}/api/v1/summary`),
        ]);

        if (mounted) {
          setAlerts(alertsResponse.data);
          setStats(summaryResponse.data);
        }
      } catch (error) {
        console.error('Unable to fetch IDS data:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [API_BASE_URL]);

  const chronologicalAlerts = [...alerts].slice(0, 20).reverse();
  const chartData = chronologicalAlerts.map((alert) => ({
    time: new Date(alert.timestamp * 1000).toLocaleTimeString(),
    confidence: Number((alert.confidence * 100).toFixed(2)),
  }));

  const topProtocol = Object.keys(stats.protocols || {}).sort(
    (a, b) => stats.protocols[b] - stats.protocols[a]
  )[0] || 'None';

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1 style={{ color: '#2c3e50' }}>🛡️ Cloud Network Sentinel</h1>
      <p>
        Node-level flow monitoring, Random Forest classification, and centralized
        alert management.
      </p>

      <div style={{ display: 'flex', gap: '20px', marginBottom: '30px', flexWrap: 'wrap' }}>
        <div style={cardStyle}>
          <h3>Alerts Received</h3>
          <p style={numberStyle}>{stats.totalAlerts || 0}</p>
        </div>
        <div style={{ ...cardStyle, borderLeft: '5px solid #dc3545' }}>
          <h3>Firewall Actions</h3>
          <p style={{ ...numberStyle, color: '#dc3545' }}>
            {stats.blockedAlerts || 0}
          </p>
        </div>
        <div style={cardStyle}>
          <h3>Top Protocol</h3>
          <p style={numberStyle}>{topProtocol}</p>
        </div>
      </div>

      <div style={chartStyle}>
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis domain={[0, 100]} label={{ value: 'Confidence (%)', angle: -90, position: 'insideLeft' }} />
            <Tooltip />
            <Legend />
            <Line
              type="monotone"
              dataKey="confidence"
              name="Malicious confidence"
              stroke="#dc3545"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <h3 style={{ marginTop: '30px' }}>Recent Alert Logs</h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px' }}>
          <thead style={{ backgroundColor: '#34495e', color: 'white' }}>
            <tr>
              <th style={thStyle}>Time</th>
              <th style={thStyle}>Agent</th>
              <th style={thStyle}>Source</th>
              <th style={thStyle}>Destination</th>
              <th style={thStyle}>Protocol</th>
              <th style={thStyle}>Confidence</th>
              <th style={thStyle}>Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 10).map((alert) => (
              <tr key={alert.id} style={{ borderBottom: '1px solid #ddd' }}>
                <td style={tdStyle}>
                  {new Date(alert.timestamp * 1000).toLocaleTimeString()}
                </td>
                <td style={tdStyle}>{alert.agent_id}</td>
                <td style={tdStyle}><strong>{alert.src_ip}</strong></td>
                <td style={tdStyle}>{alert.dst_ip}</td>
                <td style={tdStyle}>{alert.protocol}</td>
                <td style={tdStyle}>{(alert.confidence * 100).toFixed(1)}%</td>
                <td style={{ ...tdStyle, color: alert.action === 'BLOCKED' ? 'red' : '#555' }}>
                  {alert.action}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const cardStyle = {
  flex: '1 1 180px',
  backgroundColor: 'white',
  padding: '20px',
  borderRadius: '8px',
  boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
};

const numberStyle = { fontSize: '24px', fontWeight: 'bold' };
const chartStyle = {
  backgroundColor: 'white',
  padding: '20px',
  borderRadius: '8px',
  boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
};
const thStyle = { padding: '12px', textAlign: 'left' };
const tdStyle = { padding: '10px' };

export default Dashboard;
