"use client";

import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, LineChart, Line
} from 'recharts';
import {
  ShieldAlert, ScanSearch, Activity, Flame, ShieldCheck, Zap, Globe,
  Server, AlertTriangle, Clock, ArrowUpRight, ArrowDownRight, TrendingUp,
  Shield, Target, Eye, ChevronRight, Calendar, RefreshCw
} from 'lucide-react';
import axios from 'axios';
import Link from 'next/link';

interface StatEntry {
  name: string;
  value: number;
  color: string;
}

interface ScanEntry {
  id: string;
  target: string;
  status: string;
  type: string;
  createdAt: string;
  _count?: { findings: number };
  totalIps?: number;
}

interface Finding {
  ip: string;
  severity: string;
  service: string | null;
  updatedAt: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<StatEntry[]>([]);
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, scansRes, findingsRes] = await Promise.all([
          axios.get('/api/stats'),
          axios.get('/api/scans'),
          axios.get('/api/findings')
        ]);
        setStats(statsRes.data);
        setScans(scansRes.data);
        setFindings(findingsRes.data);
      } catch (error) {
        console.error('Failed to fetch dashboard data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const totalFindings = stats.reduce((acc, curr) => acc + curr.value, 0);
  const recentScans = scans.slice(0, 5);
  const criticalCount = stats.find(s => s.name === 'Critical')?.value || 0;
  const highCount = stats.find(s => s.name === 'High')?.value || 0;
  const uniqueIps = new Set(findings.filter(f => f.ip !== '0.0.0.0').map(f => f.ip)).size;
  const activeScans = scans.filter(s => s.status === 'RUNNING').length;

  // Calculate risk score (0-100)
  const riskScore = Math.min(100, Math.round(
    (criticalCount * 25 + highCount * 15 + (stats.find(s => s.name === 'Medium')?.value || 0) * 5) / Math.max(1, totalFindings) * 10
  ));

  const getRiskLevel = (score: number) => {
    if (score >= 70) return { label: 'Critical', color: 'text-red-500', bg: 'bg-red-500' };
    if (score >= 50) return { label: 'High', color: 'text-orange-500', bg: 'bg-orange-500' };
    if (score >= 30) return { label: 'Medium', color: 'text-yellow-500', bg: 'bg-yellow-500' };
    return { label: 'Low', color: 'text-green-500', bg: 'bg-green-500' };
  };

  const riskLevel = getRiskLevel(riskScore);

  // Mock trend data for sparklines
  const trendData = [
    { day: 'Mon', value: 12 },
    { day: 'Tue', value: 19 },
    { day: 'Wed', value: 15 },
    { day: 'Thu', value: 22 },
    { day: 'Fri', value: 18 },
    { day: 'Sat', value: totalFindings * 0.8 },
    { day: 'Sun', value: totalFindings },
  ];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header with Risk Score */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div>
          <h1 className="text-3xl font-black tracking-tight">Security Command Center</h1>
          <p className="text-muted-foreground mt-1">Real-time attack surface monitoring and threat intelligence</p>
        </div>
        <div className="flex items-center gap-4">
          <Link href="/scans" className="px-4 py-2 bg-primary text-primary-foreground rounded-xl font-bold text-sm hover:bg-primary/90 transition-all flex items-center gap-2">
            <ScanSearch className="w-4 h-4" />
            New Scan
          </Link>
          <button className="p-2 rounded-xl border border-border hover:bg-accent transition-all">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Risk Score Hero Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 bg-gradient-to-br from-card to-card/50 border border-border rounded-3xl p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/10 to-transparent rounded-full blur-2xl" />
          <div className="relative z-10">
            <p className="text-sm font-bold text-muted-foreground uppercase tracking-widest mb-2">Overall Risk Score</p>
            <div className="flex items-end gap-4 mb-4">
              <span className={`text-6xl font-black ${riskLevel.color}`}>{riskScore}</span>
              <span className="text-2xl text-muted-foreground font-bold mb-2">/100</span>
            </div>
            <div className="w-full h-3 bg-muted rounded-full overflow-hidden mb-3">
              <div
                className={`h-full ${riskLevel.bg} transition-all duration-1000`}
                style={{ width: `${riskScore}%` }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className={`px-3 py-1 rounded-lg text-xs font-black uppercase ${riskLevel.color} ${riskLevel.bg}/10`}>
                {riskLevel.label} Risk
              </span>
              <span className="text-xs text-muted-foreground">Last updated: Now</span>
            </div>
          </div>
        </div>

        {/* Quick Stats Grid */}
        <div className="lg:col-span-2 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-card border border-border rounded-2xl p-4 hover:border-primary/30 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-blue-500/10"><Globe className="w-4 h-4 text-blue-500" /></div>
              <TrendingUp className="w-3 h-3 text-green-500" />
            </div>
            <p className="text-2xl font-black">{uniqueIps}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Assets Discovered</p>
          </div>
          <div className="bg-card border border-red-500/20 rounded-2xl p-4 hover:border-red-500/40 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-red-500/10"><AlertTriangle className="w-4 h-4 text-red-500" /></div>
              {criticalCount > 0 && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
            </div>
            <p className="text-2xl font-black text-red-500">{criticalCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Critical Issues</p>
          </div>
          <div className="bg-card border border-orange-500/20 rounded-2xl p-4 hover:border-orange-500/40 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-orange-500/10"><Flame className="w-4 h-4 text-orange-500" /></div>
            </div>
            <p className="text-2xl font-black text-orange-500">{highCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">High Priority</p>
          </div>
          <div className="bg-card border border-border rounded-2xl p-4 hover:border-primary/30 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-purple-500/10"><ShieldAlert className="w-4 h-4 text-purple-500" /></div>
            </div>
            <p className="text-2xl font-black">{totalFindings}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Total Findings</p>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="lg:col-span-2 bg-card border border-border rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              Severity Distribution
            </h3>
            <span className="text-xs text-muted-foreground">All time</span>
          </div>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats} barSize={40}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" vertical={false} />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#666', fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#666', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', borderRadius: '12px', border: '1px solid #222', boxShadow: '0 10px 40px rgba(0,0,0,0.5)' }}
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {stats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Breakdown Donut */}
        <div className="bg-card border border-border rounded-2xl p-6">
          <h3 className="text-lg font-bold mb-4">Risk Breakdown</h3>
          <div className="h-[180px] flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stats}
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={3}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {stats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', borderRadius: '12px', border: '1px solid #222' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2 mt-4">
            {stats.map((stat, i) => (
              <div key={i} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: stat.color }} />
                  <span className="text-muted-foreground text-xs">{stat.name}</span>
                </div>
                <span className="font-bold text-xs">{stat.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row: Active Scans & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Scans */}
        <div className="bg-card border border-border rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-500" />
              Scan Operations
            </h3>
            <Link href="/scans" className="text-xs text-primary font-bold hover:underline flex items-center gap-1">
              View All <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {recentScans.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <ScanSearch className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No scans recorded yet</p>
              </div>
            ) : (
              recentScans.map((scan) => (
                <Link key={scan.id} href={`/scans/${scan.id}`} className="flex items-center justify-between p-3 rounded-xl hover:bg-accent/50 transition-all group">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${scan.status === 'COMPLETED' ? 'bg-green-500/10' :
                        scan.status === 'RUNNING' ? 'bg-blue-500/10' : 'bg-red-500/10'
                      }`}>
                      {scan.status === 'RUNNING' ? (
                        <Activity className="w-4 h-4 text-blue-500 animate-pulse" />
                      ) : scan.status === 'COMPLETED' ? (
                        <ShieldCheck className="w-4 h-4 text-green-500" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-red-500" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium text-sm group-hover:text-primary transition-colors">{scan.target}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {scan.totalIps || 0} IPs • {scan._count?.findings || 0} findings
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${scan.status === 'COMPLETED' ? 'bg-green-500/10 text-green-500' :
                        scan.status === 'RUNNING' ? 'bg-blue-500/10 text-blue-500' : 'bg-red-500/10 text-red-500'
                      }`}>
                      {scan.status}
                    </span>
                    <p className="text-[10px] text-muted-foreground mt-1">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Quick Actions & System Status */}
        <div className="bg-card border border-border rounded-2xl p-6">
          <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
            <Target className="w-5 h-5 text-primary" />
            Quick Actions
          </h3>
          <div className="grid grid-cols-2 gap-3 mb-6">
            <Link href="/scans" className="p-4 rounded-xl border border-border hover:border-primary/50 hover:bg-accent/30 transition-all text-center group">
              <ScanSearch className="w-6 h-6 mx-auto mb-2 text-primary group-hover:scale-110 transition-transform" />
              <p className="text-xs font-bold">New Scan</p>
            </Link>
            <Link href="/attack-surface" className="p-4 rounded-xl border border-border hover:border-primary/50 hover:bg-accent/30 transition-all text-center group">
              <Globe className="w-6 h-6 mx-auto mb-2 text-blue-500 group-hover:scale-110 transition-transform" />
              <p className="text-xs font-bold">Attack Surface</p>
            </Link>
            <Link href="/findings" className="p-4 rounded-xl border border-border hover:border-primary/50 hover:bg-accent/30 transition-all text-center group">
              <Eye className="w-6 h-6 mx-auto mb-2 text-purple-500 group-hover:scale-110 transition-transform" />
              <p className="text-xs font-bold">All Findings</p>
            </Link>
            <Link href="/schedules" className="p-4 rounded-xl border border-border hover:border-primary/50 hover:bg-accent/30 transition-all text-center group">
              <Calendar className="w-6 h-6 mx-auto mb-2 text-green-500 group-hover:scale-110 transition-transform" />
              <p className="text-xs font-bold">Schedules</p>
            </Link>
          </div>

          {/* System Status */}
          <div className="border-t border-border pt-4">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-3">System Status</p>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Scanning Engine</span>
                <span className="flex items-center gap-1.5 text-xs text-green-500 font-bold">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                  Operational
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Active Scans</span>
                <span className="text-xs font-bold">{activeScans}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Last Discovery</span>
                <span className="text-xs font-bold">
                  {findings.length > 0 ? new Date(findings[0].updatedAt).toLocaleTimeString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
