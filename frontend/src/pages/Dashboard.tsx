
import React from 'react';
import { Activity, TrendingUp, BarChart2, AlertTriangle, Zap, Upload, Link } from 'lucide-react';
import { StatCard } from '@/components/ui-custom/StatCard';
import { PerformanceChart } from '@/components/ui-custom/PerformanceChart';
import { NewsCard, NewsItem } from '@/components/ui-custom/NewsCard';
import { SignalTable, Signal } from '@/components/ui-custom/SignalTable';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from 'sonner';

// Mock data
const mockNews: NewsItem[] = [
  {
    headline: "Fed signals potential rate cut in upcoming meeting",
    source: "Bloomberg",
    timestamp: "10:32 AM",
    sentiment: "positive",
    impactScore: 4,
    summary: "The Federal Reserve has signaled that it may cut interest rates in the upcoming FOMC meeting, citing improving inflation data and concerns about the labor market."
  },
  {
    headline: "NVIDIA reports record quarterly revenue on AI chip demand",
    source: "CNBC",
    timestamp: "9:15 AM",
    sentiment: "positive",
    impactScore: 5,
    summary: "NVIDIA has reported record quarterly revenue, driven by unprecedented demand for its AI chips. The company has raised its future guidance."
  },
  {
    headline: "Oil prices fall amid concerns over global demand",
    source: "Reuters",
    timestamp: "11:47 AM",
    sentiment: "negative",
    impactScore: 3,
    summary: "Oil prices have fallen by 2% as concerns over global demand persist, with China's economic slowdown being a key factor."
  },
  {
    headline: "Treasury yields stabilize after recent volatility",
    source: "WSJ",
    timestamp: "10:05 AM",
    sentiment: "neutral",
    impactScore: 2,
    summary: "Treasury yields have stabilized following a period of significant volatility, as investors reassess economic data and Fed statements."
  }
];

const mockSignals: Signal[] = [
  {
    id: '1',
    timestamp: '2023-10-21 09:45',
    asset: 'AAPL',
    type: 'BUY',
    confidence: 85,
    status: 'Live'
  },
  {
    id: '2',
    timestamp: '2023-10-21 10:15',
    asset: 'TSLA',
    type: 'SELL',
    confidence: 70,
    status: 'Live'
  },
  {
    id: '3',
    timestamp: '2023-10-21 10:30',
    asset: 'BTC/USD',
    type: 'BUY',
    confidence: 65,
    status: 'Paused'
  },
  {
    id: '4',
    timestamp: '2023-10-21 11:05',
    asset: 'EUR/USD',
    type: 'SELL',
    confidence: 90,
    status: 'Live'
  }
];

const mockBacktests = [
  {
    id: '1',
    name: 'Momentum Strategy',
    dateRange: 'Jan 2023 - Oct 2023',
    profitLoss: '+18.7%'
  },
  {
    id: '2',
    name: 'Mean Reversion',
    dateRange: 'Jun 2023 - Oct 2023',
    profitLoss: '+9.2%'
  },
  {
    id: '3',
    name: 'Technical Breakout',
    dateRange: 'Mar 2023 - Oct 2023',
    profitLoss: '-2.4%'
  }
];

const Dashboard = () => {
  const handleSignalRowClick = (signal: Signal) => {
    toast.success(`Viewing details for ${signal.asset} ${signal.type} signal`);
  };
  
  const handleQuickAction = (action: string) => {
    toast.info(`${action} action triggered`);
  };

  return (
    <div className="space-y-6">
      {/* Market Status */}
      <div className="flex flex-col md:flex-row gap-6 md:gap-4">
        <Card className="flex-1 bg-graphite/30 border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-arctic/70">Market Status</CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row items-center justify-between">
              <div className="flex items-center p-2">
                <div className="h-10 w-10 rounded-full bg-neon-green/10 flex items-center justify-center mr-3">
                  <TrendingUp className="text-neon-green h-5 w-5" />
                </div>
                <div>
                  <p className="text-xs text-arctic/70">S&P 500</p>
                  <div className="flex items-center">
                    <p className="font-bold text-arctic">4,892.38</p>
                    <span className="text-neon-green text-xs ml-2">+1.2%</span>
                  </div>
                </div>
              </div>
              
              <div className="flex items-center p-2">
                <div className="h-10 w-10 rounded-full bg-electric-cyan/10 flex items-center justify-center mr-3">
                  <BarChart2 className="text-electric-cyan h-5 w-5" />
                </div>
                <div>
                  <p className="text-xs text-arctic/70">NASDAQ</p>
                  <div className="flex items-center">
                    <p className="font-bold text-arctic">16,748.24</p>
                    <span className="text-neon-green text-xs ml-2">+1.8%</span>
                  </div>
                </div>
              </div>
              
              <div className="flex items-center p-2">
                <div className="h-10 w-10 rounded-full bg-caution/10 flex items-center justify-center mr-3">
                  <Activity className="text-caution h-5 w-5" />
                </div>
                <div>
                  <p className="text-xs text-arctic/70">VIX</p>
                  <div className="flex items-center">
                    <p className="font-bold text-arctic">14.32</p>
                    <span className="text-danger text-xs ml-2">-4.2%</span>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Key Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Return"
          value="+24.7%"
          icon={<TrendingUp size={16} />}
          trend={{ value: 2.3, isPositive: true }}
        />
        <StatCard
          title="Sharpe Ratio"
          value="1.87"
          icon={<BarChart2 size={16} />}
          trend={{ value: 0.12, isPositive: true }}
        />
        <StatCard
          title="Win Rate"
          value="68.5%"
          icon={<Activity size={16} />}
          trend={{ value: 1.5, isPositive: true }}
        />
        <StatCard
          title="AI Risk Score"
          value="Medium"
          icon={<AlertTriangle size={16} />}
          trend={{ value: 5, isPositive: false }}
        />
      </div>

      {/* Portfolio Performance */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PerformanceChart title="Portfolio Performance" height={300} />
        </div>
        
        <div className="space-y-4">
          <Card className="bg-graphite/30 border-white/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-arctic/70">Backtest Summary</CardTitle>
            </CardHeader>
            <CardContent className="p-4 space-y-3">
              {mockBacktests.map(backtest => (
                <div 
                  key={backtest.id}
                  className="flex justify-between p-2 rounded-md bg-space-blue/50 hover:bg-space-blue transition-colors duration-200"
                >
                  <div>
                    <p className="text-sm font-medium text-arctic">{backtest.name}</p>
                    <p className="text-xs text-arctic/50">{backtest.dateRange}</p>
                  </div>
                  <div>
                    <span className={`text-sm font-medium px-2 py-1 rounded ${
                      backtest.profitLoss.startsWith('+') ? 'text-neon-green' : 'text-danger'
                    }`}>
                      {backtest.profitLoss}
                    </span>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
          
          <Card className="bg-graphite/30 border-white/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-arctic/70">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="p-4 grid grid-cols-3 gap-2">
              <Button 
                variant="outline" 
                className="flex flex-col items-center justify-center h-20 border-white/10 bg-space-blue hover:bg-white/5"
                onClick={() => handleQuickAction('Upload Strategy')}
              >
                <Upload size={24} className="mb-1 text-arctic/70" />
                <span className="text-xs text-arctic/70">Upload</span>
              </Button>
              <Button 
                variant="outline" 
                className="flex flex-col items-center justify-center h-20 border-white/10 bg-space-blue hover:bg-white/5"
                onClick={() => handleQuickAction('Run Backtest')}
              >
                <Zap size={24} className="mb-1 text-arctic/70" />
                <span className="text-xs text-arctic/70">Backtest</span>
              </Button>
              <Button 
                variant="outline" 
                className="flex flex-col items-center justify-center h-20 border-white/10 bg-space-blue hover:bg-white/5"
                onClick={() => handleQuickAction('Add Webhook')}
              >
                <Link size={24} className="mb-1 text-arctic/70" />
                <span className="text-xs text-arctic/70">Webhook</span>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* News and Signals */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <Tabs defaultValue="market" className="w-full">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-arctic">AI News Summary</h2>
              <TabsList className="bg-space-blue">
                <TabsTrigger value="market" className="data-[state=active]:bg-white/10">Market News</TabsTrigger>
                <TabsTrigger value="strategy" className="data-[state=active]:bg-white/10">Strategy-Relevant</TabsTrigger>
              </TabsList>
            </div>
            <TabsContent value="market" className="space-y-4 mt-0">
              {mockNews.map((item, index) => (
                <NewsCard key={index} item={item} />
              ))}
            </TabsContent>
            <TabsContent value="strategy" className="space-y-4 mt-0">
              {mockNews.slice(0, 2).map((item, index) => (
                <NewsCard key={index} item={item} />
              ))}
            </TabsContent>
          </Tabs>
        </div>
        
        <div>
          <h2 className="text-lg font-bold text-arctic mb-4">Recent Signals</h2>
          <SignalTable signals={mockSignals} onRowClick={handleSignalRowClick} />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
