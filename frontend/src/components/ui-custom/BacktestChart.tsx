
import React from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  Area,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
} from 'recharts';
import { ChartContainer, ChartTooltipContent } from '@/components/ui/chart';

// Mock data for chart
const generateBacktestData = () => {
  const data = [];
  const startDate = new Date('2023-01-01');
  let price = 150;
  let equity = 100000;
  
  for (let i = 0; i < 180; i++) {
    const date = new Date(startDate);
    date.setDate(startDate.getDate() + i);
    
    // Random price movement
    const change = (Math.random() - 0.48) * 5;
    price = Math.max(50, price + change);
    
    // Random equity changes based on strategy performance
    const equityChange = price > 145 ? Math.random() * 2000 - 800 : Math.random() * 3000 - 2000;
    equity += equityChange;
    
    // Create signals at certain points
    let signal = null;
    if (i % 15 === 0 && Math.random() > 0.5) {
      signal = Math.random() > 0.5 ? 'buy' : 'sell';
    }
    
    // Create news events occasionally
    const hasNews = i % 23 === 0 && Math.random() > 0.7;
    
    data.push({
      date: date.toISOString().split('T')[0],
      price,
      volume: Math.random() * 1000000 + 500000,
      equity,
      signal,
      signalPrice: signal ? price : null,
      news: hasNews ? 'News Event' : null,
      cotLong: Math.random() * 100000 + 300000,
      cotShort: Math.random() * 80000 + 200000
    });
  }
  
  return data;
};

const chartData = generateBacktestData();

// Chart config for custom styling
const chartConfig = {
  price: { 
    color: '#e2e8f0', 
    label: 'Price'
  },
  equity: { 
    color: '#00FF9D', 
    label: 'Equity'
  },
  volume: { 
    color: '#434c5e', 
    label: 'Volume'
  },
  cotLong: {
    color: 'rgba(0, 224, 255, 0.7)',
    label: 'COT Long'
  },
  cotShort: {
    color: 'rgba(157, 80, 255, 0.7)',
    label: 'COT Short'
  }
};

interface BacktestChartProps {
  height?: number;
  activeLayers: {
    signals: boolean;
    news: boolean;
    volume: boolean;
    cot: boolean;
  };
}

export const BacktestChart: React.FC<BacktestChartProps> = ({ height = 400, activeLayers }) => {
  return (
    <div className="w-full" style={{ height }}>
      <ChartContainer config={chartConfig} className="text-xs">
        <ComposedChart
          data={chartData}
          margin={{
            top: 20,
            right: 30,
            left: 20,
            bottom: 20,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis 
            dataKey="date" 
            stroke="rgba(255,255,255,0.5)" 
            tick={{ fill: 'rgba(255,255,255,0.5)' }}
            tickLine={{ stroke: 'rgba(255,255,255,0.2)' }}
          />
          <YAxis 
            yAxisId="price" 
            domain={['auto', 'auto']} 
            stroke="rgba(255,255,255,0.5)" 
            tick={{ fill: 'rgba(255,255,255,0.5)' }}
            tickLine={{ stroke: 'rgba(255,255,255,0.2)' }}
          />
          <YAxis 
            yAxisId="equity" 
            orientation="right"
            stroke="rgba(0,255,157,0.7)" 
            tick={{ fill: 'rgba(0,255,157,0.7)' }}
            tickLine={{ stroke: 'rgba(0,255,157,0.3)' }}
          />
          
          {activeLayers.volume && (
            <YAxis 
              yAxisId="volume" 
              orientation="left"
              domain={[0, 'dataMax']}
              hide
            />
          )}
          
          {activeLayers.cot && (
            <YAxis 
              yAxisId="cot" 
              orientation="right"
              domain={[0, 'dataMax']}
              hide
            />
          )}
          
          <Tooltip content={<ChartTooltipContent />} />
          <Legend />

          {/* Price Line */}
          <Line
            type="monotone"
            dataKey="price"
            yAxisId="price"
            stroke="#e2e8f0"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 5, stroke: '#e2e8f0', strokeWidth: 1, fill: '#0F172A' }}
          />
          
          {/* Equity Line */}
          <Line
            type="monotone"
            dataKey="equity"
            yAxisId="equity"
            stroke="#00FF9D"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 5, stroke: '#00FF9D', strokeWidth: 1, fill: '#0F172A' }}
          />
          
          {/* Volume */}
          {activeLayers.volume && (
            <Bar 
              dataKey="volume" 
              yAxisId="volume" 
              fill="rgba(67, 76, 94, 0.5)"
              name="Volume"
            />
          )}

          {/* COT Data */}
          {activeLayers.cot && (
            <>
              <Area 
                type="monotone" 
                dataKey="cotLong" 
                yAxisId="cot"
                stackId="1"
                stroke="rgba(0, 224, 255, 0.7)"
                fill="rgba(0, 224, 255, 0.2)"
              />
              <Area 
                type="monotone" 
                dataKey="cotShort" 
                yAxisId="cot"
                stackId="1"
                stroke="rgba(157, 80, 255, 0.7)"
                fill="rgba(157, 80, 255, 0.2)"
              />
            </>
          )}

          {/* Buy/Sell Signals */}
          {activeLayers.signals && chartData.map((entry, index) => {
            if (entry.signal === 'buy') {
              return (
                <ReferenceLine 
                  key={`buy-${index}`}
                  x={entry.date} 
                  stroke="#00FF9D"
                  strokeDasharray="3 3"
                  isFront={true}
                />
              );
            } else if (entry.signal === 'sell') {
              return (
                <ReferenceLine 
                  key={`sell-${index}`}
                  x={entry.date} 
                  stroke="#FF4D4D"
                  strokeDasharray="3 3"
                  isFront={true}
                />
              );
            }
            return null;
          })}
          
          {/* News Events */}
          {activeLayers.news && chartData.map((entry, index) => {
            if (entry.news) {
              return (
                <ReferenceLine 
                  key={`news-${index}`}
                  x={entry.date} 
                  stroke="#FFD600"
                  isFront={true}
                />
              );
            }
            return null;
          })}
        </ComposedChart>
      </ChartContainer>
    </div>
  );
};
