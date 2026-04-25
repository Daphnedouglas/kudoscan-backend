import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { LayoutDashboard, Bell, RefreshCw, Link, Shield, AlertTriangle, Menu } from 'lucide-react';

function App() {
  const [data, setData] = useState({ table_data: [], threat_stats: { high: 0, medium: 0, low: 0 }, target_types: [], total: 0 });
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await axios.get('http://127.0.0.1:8000/api/stats');
      setData(res.data);
    } catch (err) { 
      console.error("API Offline or Connection Refused", err); 
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
  }, []);

  const getThreatColor = (level) => {
    if (level === 'High') return 'text-red-500';
    if (level === 'Medium') return 'text-yellow-500';
    if (level === 'Low') return 'text-emerald-500';
    return 'text-gray-400';
  };

  return (
    <div className="flex h-screen w-full bg-[#0b0e14] text-white overflow-hidden relative">
      
      {/* Background Purple Glows */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-purple-900/30 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-indigo-900/20 rounded-full blur-[100px] pointer-events-none"></div>

      {/* SIDEBAR */}
      <div className="w-64 h-full flex-shrink-0 border-r border-white/10 bg-[#0b0e14]/80 backdrop-blur-xl z-10 p-6 flex flex-col">
        <div className="flex items-center gap-3 mb-12">
          {/* Replaced Shield with Menu Icon */}
          <Menu className="text-purple-500" size={32} />
          <h2 className="text-2xl font-bold tracking-wider">Menu</h2>
        </div>
        <nav className="flex flex-col gap-2">
          <button className="flex items-center gap-4 bg-purple-600/20 text-purple-400 px-4 py-3 rounded-xl transition-all border border-purple-500/30">
            <LayoutDashboard size={20} /> Dashboard
          </button>
          <button className="flex items-center justify-between text-gray-400 hover:bg-white/5 hover:text-white px-4 py-3 rounded-xl transition-all">
            <div className="flex items-center gap-4"><Bell size={20} /> Notification</div>
            <span className="bg-red-500 text-white text-xs font-bold px-2 py-0.5 rounded-full">4</span>
          </button>
        </nav>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 h-full overflow-y-auto custom-scrollbar p-8 lg:p-10 z-10 flex flex-col">
        
        {/* Top Bar */}
        <div className="flex justify-between items-end mb-8 flex-shrink-0">
          <div>
            <h1 className="text-4xl font-bold tracking-tight">KudoScan Analysis Dashboard</h1>
            <p className="text-gray-400 mt-2">Stay Ahead of Threats, Stay Secure.</p>
          </div>
          {/* Upgraded Purple Hover Button */}
          <button 
            onClick={fetchData} 
            className="flex items-center gap-2 bg-white/5 hover:bg-purple-800/30 hover:border-purple-600/40 hover:text-purple-300 border border-white/10 px-6 py-3 rounded-xl transition-all font-medium"
          >
            <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
            Refresh Data
          </button>
        </div>

        {/* Top Boxes Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8 flex-shrink-0">
          
          {/* Left Box */}
          <div className="bg-white/[0.02] backdrop-blur-3xl p-8 rounded-3xl border border-white/[0.08] shadow-[0_8px_32px_0_rgba(0,0,0,0.3)]">
            <h3 className="text-gray-400 font-medium mb-6">Threats Detected This Week</h3>
            <div className="flex justify-around items-center">
              <div className="flex flex-col items-center gap-3">
                <div className="w-24 h-24 rounded-full border-8 border-red-500/20 flex items-center justify-center border-t-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
                  <span className="text-xl font-bold text-red-500">{data.threat_stats.high}%</span>
                </div>
                <span className="text-sm font-medium text-red-400">High Risk</span>
              </div>
              <div className="flex flex-col items-center gap-3">
                <div className="w-24 h-24 rounded-full border-8 border-yellow-500/20 flex items-center justify-center border-t-yellow-500 shadow-[0_0_15px_rgba(234,179,8,0.2)]">
                  <span className="text-xl font-bold text-yellow-500">{data.threat_stats.medium}%</span>
                </div>
                <span className="text-sm font-medium text-yellow-400">Medium</span>
              </div>
              <div className="flex flex-col items-center gap-3">
                <div className="w-24 h-24 rounded-full border-8 border-emerald-500/20 flex items-center justify-center border-t-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                  <span className="text-xl font-bold text-emerald-500">{data.threat_stats.low}%</span>
                </div>
                <span className="text-sm font-medium text-emerald-400">Low Risk</span>
              </div>
            </div>
          </div>

          {/* Right Box */}
          <div className="bg-white/[0.02] backdrop-blur-3xl p-8 rounded-3xl border border-white/[0.08] shadow-[0_8px_32px_0_rgba(0,0,0,0.3)] flex flex-col">
            <h3 className="text-gray-400 font-medium mb-6">Attack Vectors (Target Types)</h3>
            <div className="space-y-4 overflow-y-auto custom-scrollbar pr-2 max-h-[150px]">
              {data.target_types.length === 0 ? (
                <div className="text-gray-500">No data available</div>
              ) : (
                data.target_types.map((type, index) => (
                  <div key={index} className="flex items-center justify-between bg-white/5 p-4 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-3">
                      {type.name === 'URL' ? <Link className="text-blue-400" /> : <Shield className="text-purple-400"/>}
                      <span className="font-medium text-lg">{type.name}</span>
                    </div>
                    <span className="text-xl font-bold">{type.count}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Bottom Table */}
        <div className="bg-white/[0.02] backdrop-blur-3xl rounded-3xl border border-white/[0.08] shadow-[0_8px_32px_0_rgba(0,0,0,0.3)] flex flex-col mb-10">
          
          <div className="p-6 border-b border-white/10 flex justify-between items-center bg-gradient-to-r from-white/[0.05] to-transparent rounded-t-3xl">
            <h2 className="font-semibold text-lg flex items-center gap-2">
              
              Live Scan Database
            </h2>
          </div>
          
          <div className="p-2 overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead className="text-gray-400 text-sm">
                <tr>
                  <th className="p-5 font-medium border-b border-white/5">Time & Date</th>
                  <th className="p-5 font-medium border-b border-white/5">Target Type</th>
                  <th className="p-5 font-medium border-b border-white/5">Target Value</th>
                  <th className="p-5 font-medium border-b border-white/5">Threat Level</th>
                  <th className="p-5 font-medium border-b border-white/5">Recommended Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {data.table_data.map((row, i) => (
                  <tr key={i} className="hover:bg-white/[0.04] transition-colors group">
                    <td className="p-5 text-gray-300 text-sm whitespace-nowrap">{row.timestamp}</td>
                    <td className="p-5 text-gray-300 font-medium">{row.target_type}</td>
                    <td className="p-5 font-mono text-sm text-indigo-300 truncate max-w-xs">{row.target_value}</td>
                    <td className="p-5 font-bold">
                      <span className={getThreatColor(row.threat_level)}>
                        {row.threat_level}
                      </span>
                    </td>
                    <td className="p-5 text-gray-400 text-sm">{row.recommended_action}</td>
                  </tr>
                ))}
                {data.table_data.length === 0 && (
                  <tr>
                    <td colSpan="5" className="p-12 text-center text-gray-500 font-medium">
                      No threats logged yet. Waiting for input...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;