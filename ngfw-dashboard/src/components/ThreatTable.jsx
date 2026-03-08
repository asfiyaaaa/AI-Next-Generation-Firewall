import React from 'react';
import './ThreatTable.css';

const ThreatTable = ({ threats }) => {
    return (
        <div className="threat-table-container">
            <table className="threats-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {threats.map((threat, index) => (
                        <tr key={index} className="fade-in" style={{ animationDelay: `${index * 0.05}s` }}>
                            <td>{threat.timestamp}</td>
                            <td className="mono">{threat.source_ip}</td>
                            <td className="mono">{threat.destination}</td>
                            <td>{threat.type}</td>
                            <td>
                                <span className={`severity ${threat.severity.toLowerCase()}`}>
                                    {threat.severity}
                                </span>
                            </td>
                            <td>
                                <span className={`action ${threat.action.toLowerCase()}`}>
                                    {threat.action}
                                </span>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default ThreatTable;
