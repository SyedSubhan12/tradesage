import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

// Mock performance metrics
const performanceMetrics = {
  totalReturn: 24.7,
  annualizedReturn: 21.3,
  sharpeRatio: 1.87,
  sortino: 2.05,
  maxDrawdown: 12.4,
  maxDrawdownDuration: '34 days',
  winRate: 68.5,
  profitFactor: 2.3,
  expectancy: 1.45,
  trades: 142,
  averageTrade: '+0.21%',
  averageDuration: '3.2 days',
  bestTrade: '+4.7%',
  worstTrade: '-2.1%'
};

// Mock monthly returns data
const monthlyReturns = [
  { name: 'Jan', return: 3.2 },
  { name: 'Feb', return: 1.7 },
  { name: 'Mar', return: -1.3 },
  { name: 'Apr', return: 2.8 },
  { name: 'May', return: 4.5 },
  { name: 'Jun', return: -0.8 },
  { name: 'Jul', return: 5.1 },
  { name: 'Aug', return: 2.3 },
  { name: 'Sep', return: -2.1 },
  { name: 'Oct', return: 3.7 },
  { name: 'Nov', return: 4.2 },
  { name: 'Dec', return: 1.8 },
];

// Mock trade distribution data
const tradeDistribution = [
  { name: 'Winning Trades', value: 97 },
  { name: 'Losing Trades', value: 45 },
];

// Mock drawdown data
const drawdowns = [
  { id: 1, start: '2023-03-15', end: '2023-04-18', depth: 12.4, recovery: '34 days' },
  { id: 2, start: '2023-06-22', end: '2023-06-29', depth: 5.8, recovery: '7 days' },
  { id: 3, start: '2023-09-05', end: '2023-09-18', depth: 8.2, recovery: '13 days' },
];

// Colors
const COLORS = ['#00FF9D', '#FF4D4D'];

export const BacktestMetrics: React.FC = () => {
  const [tab, setTab] = useState('overview');

  return (
    <Card className="bg-graphite/30 border-white/10">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-center">
          <CardTitle className="text-sm font-medium text-arctic/70">Performance Metrics</CardTitle>
          <Tabs value={tab} onValueChange={setTab} className="w-auto">
            <TabsList className="bg-space-blue">
              <TabsTrigger value="overview" className="data-[state=active]:bg-white/10">Overview</TabsTrigger>
              <TabsTrigger value="monthly" className="data-[state=active]:bg-white/10">Monthly</TabsTrigger>
              <TabsTrigger value="drawdowns" className="data-[state=active]:bg-white/10">Drawdowns</TabsTrigger>
              <TabsTrigger value="trades" className="data-[state=active]:bg-white/10">Trades</TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </CardHeader>
      <CardContent className="p-4">
        <TabsContent value="overview" className="mt-0 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-medium text-arctic/70 mb-2">Key Performance</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Total Return</div>
                    <div className={`text-xl font-medium ${performanceMetrics.totalReturn > 0 ? 'text-neon-green' : 'text-danger'}`}>
                      {performanceMetrics.totalReturn > 0 ? '+' : ''}{performanceMetrics.totalReturn}%
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Annualized</div>
                    <div className={`text-xl font-medium ${performanceMetrics.annualizedReturn > 0 ? 'text-neon-green' : 'text-danger'}`}>
                      {performanceMetrics.annualizedReturn > 0 ? '+' : ''}{performanceMetrics.annualizedReturn}%
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Win Rate</div>
                    <div className="text-xl font-medium text-arctic">
                      {performanceMetrics.winRate}%
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Profit Factor</div>
                    <div className="text-xl font-medium text-arctic">
                      {performanceMetrics.profitFactor}
                    </div>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-sm font-medium text-arctic/70 mb-2">Risk Metrics</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Sharpe Ratio</div>
                    <div className="text-xl font-medium text-arctic">
                      {performanceMetrics.sharpeRatio}
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Sortino Ratio</div>
                    <div className="text-xl font-medium text-arctic">
                      {performanceMetrics.sortino}
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Max Drawdown</div>
                    <div className="text-xl font-medium text-danger">
                      {performanceMetrics.maxDrawdown}%
                    </div>
                  </div>
                  <div className="bg-space-blue/50 p-3 rounded-md">
                    <div className="text-xs text-arctic/70">Recovery</div>
                    <div className="text-xl font-medium text-arctic">
                      {performanceMetrics.maxDrawdownDuration}
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="space-y-4">
              <h3 className="text-sm font-medium text-arctic/70">Trade Distribution</h3>
              <div className="h-64 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={tradeDistribution}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {tradeDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="col-span-1 lg:col-span-1">
              <h3 className="text-sm font-medium text-arctic/70 mb-2">Trade Statistics</h3>
              <div className="bg-space-blue/50 p-4 rounded-md space-y-3">
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Total Trades</span>
                  <span className="text-xs font-medium text-arctic">{performanceMetrics.trades}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Average Trade</span>
                  <span className={`text-xs font-medium ${performanceMetrics.averageTrade.startsWith('+') ? 'text-neon-green' : 'text-danger'}`}>
                    {performanceMetrics.averageTrade}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Average Duration</span>
                  <span className="text-xs font-medium text-arctic">{performanceMetrics.averageDuration}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Best Trade</span>
                  <span className="text-xs font-medium text-neon-green">{performanceMetrics.bestTrade}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Worst Trade</span>
                  <span className="text-xs font-medium text-danger">{performanceMetrics.worstTrade}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Expectancy</span>
                  <span className="text-xs font-medium text-arctic">{performanceMetrics.expectancy}</span>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="monthly" className="mt-0">
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={monthlyReturns}
                margin={{
                  top: 20,
                  right: 30,
                  left: 20,
                  bottom: 5,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="name" stroke="rgba(255,255,255,0.5)" />
                <YAxis stroke="rgba(255,255,255,0.5)" />
                <Tooltip />
                <Legend />
                <Bar dataKey="return" name="Monthly Return %">
                  {monthlyReturns.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.return >= 0 ? '#00FF9D' : '#FF4D4D'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </TabsContent>
        
        <TabsContent value="drawdowns" className="mt-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-white/10">
                <TableHead className="text-arctic/70">Start Date</TableHead>
                <TableHead className="text-arctic/70">End Date</TableHead>
                <TableHead className="text-arctic/70">Depth</TableHead>
                <TableHead className="text-arctic/70">Recovery</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {drawdowns.map((drawdown) => (
                <TableRow key={drawdown.id} className="border-white/10">
                  <TableCell className="font-medium text-arctic">{drawdown.start}</TableCell>
                  <TableCell className="text-arctic">{drawdown.end}</TableCell>
                  <TableCell className="text-danger">-{drawdown.depth}%</TableCell>
                  <TableCell className="text-arctic">{drawdown.recovery}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TabsContent>
        
        <TabsContent value="trades" className="mt-0">
          <div className="text-center text-arctic/70 py-12">
            <p>Trade analysis view will be available in the next release.</p>
          </div>
        </TabsContent>
      </CardContent>
    </Card>
  );
};
