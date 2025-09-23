
import React, { useEffect } from 'react';
import { Activity, TrendingUp, BarChart2, AlertTriangle, Zap, Upload, Link, RefreshCw } from 'lucide-react';
import { StatCard } from '@/components/ui-custom/StatCard';
import { PerformanceChart } from '@/components/ui-custom/PerformanceChart';
import { NewsCard, NewsItem } from '@/components/ui-custom/NewsCard';
import { SignalTable, Signal } from '@/components/ui-custom/SignalTable';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from 'sonner';
import { useAnalytics } from '@/hooks/useAnalytics';

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
  const {
    personalization,
    marketData,
    preferences,
    loading,
    error,
    trackInteraction,
    simulateActivity,
    refreshData
  } = useAnalytics();

  const handleSignalRowClick = (signal: Signal) => {
    // Track signal click interaction
    trackInteraction({
      interaction_type: 'signal_click',
      metadata: {
        signal_id: signal.id,
        asset: signal.asset,
        type: signal.type,
        confidence: signal.confidence
      }
    });
    toast.success(`Viewing details for ${signal.asset} ${signal.type} signal`);
  };
  
  const handleQuickAction = (action: string) => {
    // Track quick action interaction
    trackInteraction({
      interaction_type: action.toLowerCase().replace(' ', '_'),
      metadata: {
        action: action,
        timestamp: new Date().toISOString()
      }
    });
    toast.info(`${action} action triggered`);
  };

  const handleNewsClick = (newsItem: NewsItem) => {
    // Track news click interaction
    trackInteraction({
      interaction_type: 'news_click',
      metadata: {
        headline: newsItem.headline,
        source: newsItem.source,
        sentiment: newsItem.sentiment,
        category: 'market'
      }
    });
  };

  const handleSymbolView = (symbol: string, dataset: string) => {
    // Track symbol view interaction
    trackInteraction({
      interaction_type: 'symbol_view',
      metadata: {
        symbol: symbol,
        dataset: dataset,
        timestamp: new Date().toISOString()
      }
    });
  };

  // Show loading state
  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-center p-8">
          <RefreshCw className="animate-spin h-8 w-8 text-arctic/50" />
          <span className="ml-2 text-arctic/70">Loading personalized dashboard...</span>
        </div>
      </div>
    );
  }

  // Show error state
  if (error) {
    return (
      <div className="space-y-6">
        <Card className="bg-danger/10 border-danger/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <AlertTriangle className="h-5 w-5 text-danger mr-2" />
                <span className="text-danger">Error loading dashboard: {error}</span>
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={refreshData}
                className="border-danger/20 text-danger hover:bg-danger/10"
              >
                <RefreshCw className="h-4 w-4 mr-1" />
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Get dynamic market indices or fallback to defaults
  const marketIndices = marketData?.priority_indices || [
    { name: "S&P 500", value: "4,892.38", change: "+1.2%", positive: true },
    { name: "NASDAQ", value: "16,748.24", change: "+1.8%", positive: true },
    { name: "VIX", value: "14.32", change: "-4.2%", positive: false }
  ];

  return (
    <div className="space-y-6">
      {/* Analytics Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <h1 className="text-2xl font-bold text-arctic">Personalized Dashboard</h1>
          {preferences && (
            <span className="text-xs bg-electric-cyan/20 text-electric-cyan px-2 py-1 rounded">
              {preferences.trading_style.replace('_', ' ').toUpperCase()}
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={simulateActivity}
            className="border-white/10 text-arctic/70 hover:bg-white/5"
          >
            <Zap className="h-4 w-4 mr-1" />
            Simulate Activity
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={refreshData}
            className="border-white/10 text-arctic/70 hover:bg-white/5"
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Dynamic Market Status */}
      <div className="flex flex-col md:flex-row gap-6 md:gap-4">
        <Card className="flex-1 bg-graphite/30 border-white/10">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-arctic/70">
                Market Status {marketData?.market_focus && `(${marketData.market_focus.join(', ')})`}
              </CardTitle>
              {preferences && (
                <span className="text-xs text-arctic/50">
                  Risk: {preferences.risk_tolerance}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row items-center justify-between">
              {marketIndices.map((index, i) => {
                const getIcon = (name: string) => {
                  if (name.includes('VIX')) return Activity;
                  if (name.includes('NASDAQ') || name.includes('BTC') || name.includes('ETH')) return BarChart2;
                  return TrendingUp;
                };
                
                const getIconColor = (name: string, positive: boolean) => {
                  if (name.includes('VIX')) return 'text-caution';
                  if (name.includes('BTC') || name.includes('ETH')) return 'text-electric-cyan';
                  return positive ? 'text-neon-green' : 'text-danger';
                };
                
                const getBgColor = (name: string) => {
                  if (name.includes('VIX')) return 'bg-caution/10';
                  if (name.includes('BTC') || name.includes('ETH')) return 'bg-electric-cyan/10';
                  return 'bg-neon-green/10';
                };
                
                const IconComponent = getIcon(index.name);
                
                return (
                  <div key={i} className="flex items-center p-2">
                    <div className={`h-10 w-10 rounded-full ${getBgColor(index.name)} flex items-center justify-center mr-3`}>
                      <IconComponent className={`${getIconColor(index.name, index.positive)} h-5 w-5`} />
                    </div>
                    <div>
                      <p className="text-xs text-arctic/70">{index.name}</p>
                      <div className="flex items-center">
                        <p className="font-bold text-arctic">{index.value}</p>
                        <span className={`text-xs ml-2 ${
                          index.positive ? 'text-neon-green' : 'text-danger'
                        }`}>
                          {index.change}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* User's Priority Symbols */}
      {personalization?.priority_symbols && personalization.priority_symbols.length > 0 && (
        <Card className="bg-graphite/30 border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-arctic/70">Your Priority Symbols</CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {personalization.priority_symbols.map((symbolData, index) => (
                <div 
                  key={index}
                  className="bg-space-blue/50 hover:bg-space-blue transition-colors duration-200 p-3 rounded-md cursor-pointer"
                  onClick={() => handleSymbolView(symbolData.symbol, symbolData.dataset)}
                >
                  <div className="text-center">
                    <p className="font-medium text-arctic text-sm">{symbolData.symbol}</p>
                    <p className="text-xs text-arctic/50">{symbolData.dataset}</p>
                    <div className="flex items-center justify-center mt-1">
                      {Array.from({ length: symbolData.priority }, (_, i) => (
                        <div key={i} className="w-1 h-1 bg-electric-cyan rounded-full mx-0.5" />
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key Stats - Enhanced with Risk Tolerance */}
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
          title={preferences?.risk_tolerance ? `Risk (${preferences.risk_tolerance})` : "AI Risk Score"}
          value={preferences?.risk_tolerance === 'low' ? 'Conservative' : preferences?.risk_tolerance === 'high' ? 'Aggressive' : 'Medium'}
          icon={<AlertTriangle size={16} />}
          trend={{ 
            value: preferences?.risk_tolerance === 'low' ? -2 : preferences?.risk_tolerance === 'high' ? 8 : 5, 
            isPositive: preferences?.risk_tolerance === 'high' 
          }}
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
              {mockNews.map((item, index) => {
                // Check if news is relevant based on user's keywords
                const isRelevant = personalization?.relevant_news_keywords.some(keyword => 
                  item.headline.toLowerCase().includes(keyword.toLowerCase()) ||
                  item.summary.toLowerCase().includes(keyword.toLowerCase())
                ) || false;
                
                return (
                  <div key={index} className={isRelevant ? 'ring-1 ring-electric-cyan/30' : ''}>
                    <NewsCard 
                      item={{
                        ...item,
                        headline: isRelevant ? `⭐ ${item.headline}` : item.headline
                      }} 
                      onClick={() => handleNewsClick(item)}
                    />
                  </div>
                );
              })}
            </TabsContent>
            <TabsContent value="strategy" className="space-y-4 mt-0">
              {mockNews.filter((item, index) => {
                // Filter news based on user's preferred symbols and trading style
                const hasRelevantSymbol = personalization?.priority_symbols.some(symbol => 
                  item.headline.toLowerCase().includes(symbol.symbol.toLowerCase()) ||
                  item.summary.toLowerCase().includes(symbol.symbol.toLowerCase())
                ) || false;
                
                const isTradingStyleRelevant = preferences?.trading_style && (
                  (preferences.trading_style === 'day_trader' && (item.headline.includes('earnings') || item.headline.includes('volatility'))) ||
                  (preferences.trading_style === 'swing_trader' && (item.headline.includes('technical') || item.headline.includes('momentum'))) ||
                  (preferences.trading_style === 'long_term' && (item.headline.includes('dividend') || item.headline.includes('growth')))
                );
                
                return hasRelevantSymbol || isTradingStyleRelevant;
              }).map((item, index) => (
                <NewsCard 
                  key={index} 
                  item={item} 
                  onClick={() => handleNewsClick(item)}
                />
              ))}
              {mockNews.filter((item, index) => {
                const hasRelevantSymbol = personalization?.priority_symbols.some(symbol => 
                  item.headline.toLowerCase().includes(symbol.symbol.toLowerCase())
                ) || false;
                const isTradingStyleRelevant = preferences?.trading_style && (
                  (preferences.trading_style === 'day_trader' && (item.headline.includes('earnings') || item.headline.includes('volatility'))) ||
                  (preferences.trading_style === 'swing_trader' && (item.headline.includes('technical') || item.headline.includes('momentum'))) ||
                  (preferences.trading_style === 'long_term' && (item.headline.includes('dividend') || item.headline.includes('growth')))
                );
                return hasRelevantSymbol || isTradingStyleRelevant;
              }).length === 0 && (
                <div className="text-center p-4 text-arctic/50">
                  <p>No strategy-relevant news found.</p>
                  <p className="text-xs mt-1">News will appear here based on your trading activity.</p>
                </div>
              )}
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
