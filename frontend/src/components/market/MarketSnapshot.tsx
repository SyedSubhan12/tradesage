
import React from 'react';
import { motion } from 'framer-motion';
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';

const marketData = [
  { time: '9:00', BTC: 35000, ETH: 2400, SPY: 450 },
  { time: '10:00', BTC: 35200, ETH: 2380, SPY: 451 },
  { time: '11:00', BTC: 35600, ETH: 2420, SPY: 452 },
  { time: '12:00', BTC: 36000, ETH: 2450, SPY: 454 },
  { time: '13:00', BTC: 35800, ETH: 2430, SPY: 453 },
  { time: '14:00', BTC: 36200, ETH: 2470, SPY: 455 },
  { time: '15:00', BTC: 36500, ETH: 2500, SPY: 456 },
];

// Market movers data
const marketMovers = [
  { symbol: 'BTC/USD', name: 'Bitcoin', price: 36500, change: 4.2 },
  { symbol: 'ETH/USD', name: 'Ethereum', price: 2500, change: 3.8 },
  { symbol: 'SPY', name: 'S&P 500 ETF', price: 456, change: 0.7 },
  { symbol: 'AAPL', name: 'Apple Inc', price: 182.5, change: 1.2 },
  { symbol: 'NVDA', name: 'NVIDIA Corp', price: 780.3, change: -0.5 },
];

const MarketSnapshot = () => {
  return (
    <div>
      <div className="flex flex-wrap gap-6 justify-between items-start">
        <div className="w-full lg:w-7/12">
          <h3 className="text-lg font-semibold text-arctic mb-4">Today's Market Overview</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={marketData}>
                <XAxis 
                  dataKey="time" 
                  stroke="#f8fafc40" 
                  tick={{ fill: '#f8fafc80' }} 
                />
                <YAxis 
                  stroke="#f8fafc40" 
                  tick={{ fill: '#f8fafc80' }} 
                  width={40} 
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1E293B', 
                    borderColor: '#ffffff20',
                    borderRadius: '6px',
                    color: '#F8FAFC' 
                  }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="BTC" 
                  stroke="#00FF9D" 
                  strokeWidth={2} 
                  dot={false} 
                  activeDot={{ r: 4, stroke: '#00FF9D', strokeWidth: 2, fill: '#0F172A' }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="ETH" 
                  stroke="#00E0FF" 
                  strokeWidth={2} 
                  dot={false} 
                  activeDot={{ r: 4, stroke: '#00E0FF', strokeWidth: 2, fill: '#0F172A' }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="SPY" 
                  stroke="#9D50FF" 
                  strokeWidth={2} 
                  dot={false} 
                  activeDot={{ r: 4, stroke: '#9D50FF', strokeWidth: 2, fill: '#0F172A' }} 
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 mt-4">
            <div className="flex items-center">
              <div className="h-3 w-3 rounded-full bg-neon-green mr-2"></div>
              <span className="text-sm text-arctic/80">BTC/USD</span>
            </div>
            <div className="flex items-center">
              <div className="h-3 w-3 rounded-full bg-electric-cyan mr-2"></div>
              <span className="text-sm text-arctic/80">ETH/USD</span>
            </div>
            <div className="flex items-center">
              <div className="h-3 w-3 rounded-full bg-plasma-purple mr-2"></div>
              <span className="text-sm text-arctic/80">SPY</span>
            </div>
          </div>
        </div>
        
        <div className="w-full lg:w-4/12">
          <h3 className="text-lg font-semibold text-arctic mb-4">Market Movers</h3>
          <div className="space-y-3">
            {marketMovers.map((item, index) => (
              <motion.div 
                key={item.symbol} 
                className="flex justify-between items-center p-3 rounded-lg bg-white/5 border border-white/10"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1, duration: 0.3 }}
              >
                <div className="flex items-center">
                  <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                    item.change > 0 ? 'bg-neon-green/20' : 'bg-danger/20'
                  }`}>
                    <span className={`text-xs font-medium ${
                      item.change > 0 ? 'text-neon-green' : 'text-danger'
                    }`}>{item.symbol.slice(0, 2)}</span>
                  </div>
                  <div className="ml-3">
                    <div className="text-arctic font-medium">{item.symbol}</div>
                    <div className="text-xs text-arctic/50">{item.name}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-arctic">${item.price.toLocaleString()}</div>
                  <div className={item.change > 0 ? 'text-neon-green' : 'text-danger'}>
                    {item.change > 0 ? '+' : ''}{item.change}%
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MarketSnapshot;
