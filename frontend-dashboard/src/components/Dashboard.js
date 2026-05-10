import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const Dashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({ total: 0, malicious: 0, protocols: {} });

    // FIX: Use 127.0.0.1 explicitly to avoid localhost resolution issues in some browsers/OS
    const API_BASE_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:8000";

    const fetchData = async () => {
        try {
            // Note: If you encounter issues, check the browser console for CORS errors.
            // The backend MUST have CORS middleware enabled.
            const response = await axios.get(`${API_BASE_URL}/api/v1/alerts`);
            const data = response.data;
            setAlerts(data);

            // Calculate simple stats for the dashboard
            const protocolCount = {};
            data.forEach(alert => {
                protocolCount[alert.protocol] = (protocolCount[alert.protocol] || 0) + 1;
            });
            
            setStats({
                total: data.length * 5, // Simulation: assuming 1 alert per 5 packets
                malicious: data.length,
                protocols: protocolCount
            });

        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    // Chart Configuration
    const chartData = {
        labels: alerts.slice(0, 20).map(a => new Date(a.timestamp * 1000).toLocaleTimeString()),
        datasets: [
            {
                label: 'Malicious Traffic Intensity',
                data: alerts.slice(0, 20).map(a => a.length),
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.5)',
            },
        ],
    };

    const options = {
        responsive: true,
        plugins: {
            legend: { position: 'top' },
            title: { display: true, text: 'Real-Time Threat Detection Timeline' },
        },
    };

    return (
        <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
            <h1 style={{ color: '#2c3e50' }}>🛡️ Cloud Network Sentinel Dashboard</h1>
            
            <div style={{ display: 'flex', gap: '20px', marginBottom: '30px' }}>
                <div style={cardStyle}>
                    <h3>Total Traffic Analyzed</h3>
                    <p style={{ fontSize: '24px', fontWeight: 'bold' }}>{stats.total}</p>
                </div>
                <div style={{ ...cardStyle, borderLeft: '5px solid red' }}>
                    <h3>Threats Detected</h3>
                    <p style={{ fontSize: '24px', fontWeight: 'bold', color: 'red' }}>{stats.malicious}</p>
                </div>
                <div style={cardStyle}>
                    <h3>Top Protocol</h3>
                    <p style={{ fontSize: '24px', fontWeight: 'bold' }}>
                        {Object.keys(stats.protocols).sort((a,b) => stats.protocols[b]-stats.protocols[a])[0] || "None"}
                    </p>
                </div>
            </div>

            <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
                <Line options={options} data={chartData} />
            </div>

            <h3 style={{ marginTop: '30px' }}>Recent Alert Logs</h3>
            <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px' }}>
                <thead style={{ backgroundColor: '#34495e', color: 'white' }}>
                    <tr>
                        <th style={thStyle}>Time</th>
                        <th style={thStyle}>Source IP</th>
                        <th style={thStyle}>Destination</th>
                        <th style={thStyle}>Protocol</th>
                        <th style={thStyle}>Action Taken</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.slice(0, 10).map((alert, index) => (
                        <tr key={index} style={{ borderBottom: '1px solid #ddd' }}>
                            <td style={tdStyle}>{new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
                            <td style={tdStyle}><strong>{alert.src_ip}</strong></td>
                            <td style={tdStyle}>{alert.dst_ip}</td>
                            <td style={tdStyle}>{alert.protocol}</td>
                            <td style={{...tdStyle, color: 'red'}}>🚫 BLOCKED</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

const cardStyle = {
    flex: 1,
    backgroundColor: 'white',
    padding: '20px',
    borderRadius: '8px',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
};

const thStyle = { padding: '12px', textAlign: 'left' };
const tdStyle = { padding: '10px' };

export default Dashboard;