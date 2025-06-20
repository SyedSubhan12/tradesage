
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Search, Filter, PlusCircle } from 'lucide-react';
import { StrategyCard } from '@/components/ui-custom/StrategyCard';

// Mock data
const mockStrategies = [
  {
    id: '1',
    name: 'Mean Reversion ETF Strategy',
    description: 'Capitalizes on the tendency of asset prices to revert to their mean values over time.',
    author: 'John Doe',
    version: '1.3.0',
    lastModified: 'Oct 21, 2023',
    status: 'Active' as const,
    assetClass: 'ETF',
    riskLevel: 'Medium' as const,
    codeSnippet: `def calculate_signal(data):
    # Calculate Z-score
    rolling_mean = data['close'].rolling(window=20).mean()
    rolling_std = data['close'].rolling(window=20).std()
    z_score = (data['close'] - rolling_mean) / rolling_std
    
    # Generate signals
    signals = pd.Series(0, index=data.index)
    signals[z_score < -1.5] = 1  # Buy signal
    signals[z_score > 1.5] = -1  # Sell signal
    return signals`
  },
  {
    id: '2',
    name: 'Momentum Breakout Detection',
    description: 'Identifies breakout points in price movement to capture momentum-based trading opportunities.',
    author: 'Jane Smith',
    version: '2.1.0',
    lastModified: 'Oct 19, 2023',
    status: 'Backtesting' as const,
    assetClass: 'Crypto',
    riskLevel: 'High' as const,
    codeSnippet: `def detect_breakout(data, lookback=20, threshold=0.03):
    # Find local highs and lows
    rolling_max = data['high'].rolling(window=lookback).max()
    rolling_min = data['low'].rolling(window=lookback).min()
    
    # Generate signals on breakouts
    buy_signal = data['close'] > rolling_max * (1 + threshold)
    sell_signal = data['close'] < rolling_min * (1 - threshold)
    
    return buy_signal, sell_signal`
  },
  {
    id: '3',
    name: 'Pairs Trading Strategy',
    description: 'Exploits the correlation between two assets to profit from temporary divergences in their price relationship.',
    author: 'Michael Lee',
    version: '1.0.5',
    lastModified: 'Oct 15, 2023',
    status: 'Paused' as const,
    assetClass: 'Equities',
    riskLevel: 'Low' as const,
    codeSnippet: `def pairs_strategy(asset1, asset2, z_threshold=2.0):
    # Calculate spread between assets
    spread = np.log(asset1 / asset2)
    
    # Calculate z-score of spread
    mean = np.mean(spread)
    std = np.std(spread)
    z_score = (spread - mean) / std
    
    # Generate signals
    long_entry = z_score < -z_threshold
    short_entry = z_score > z_threshold`
  },
  {
    id: '4',
    name: 'Trend-Following SMA Crossover',
    description: 'Identifies trend changes using simple moving average crossovers for accurate market timing.',
    author: 'Sarah Johnson',
    version: '3.2.1',
    lastModified: 'Oct 12, 2023',
    status: 'Active' as const,
    assetClass: 'Futures',
    riskLevel: 'Medium' as const,
    codeSnippet: `def sma_crossover(data, fast=20, slow=50):
    # Calculate moving averages
    fast_ma = data['close'].rolling(window=fast).mean()
    slow_ma = data['close'].rolling(window=slow).mean()
    
    # Generate signals on crossovers
    buy_signal = (fast_ma > slow_ma) & (fast_ma.shift(1) <= slow_ma.shift(1))
    sell_signal = (fast_ma < slow_ma) & (fast_ma.shift(1) >= slow_ma.shift(1))
    
    return buy_signal, sell_signal`
  }
];

const Strategies = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string | null>(null);
  const [selectedAssetClass, setSelectedAssetClass] = useState<string | null>(null);
  const [selectedRiskLevel, setSelectedRiskLevel] = useState<string | null>(null);
  
  // Get unique values for filters
  const statuses = Array.from(new Set(mockStrategies.map(s => s.status)));
  const assetClasses = Array.from(new Set(mockStrategies.map(s => s.assetClass)));
  const riskLevels = Array.from(new Set(mockStrategies.map(s => s.riskLevel)));
  
  // Filter strategies based on search and filters
  const filteredStrategies = mockStrategies.filter(strategy => {
    const matchesSearch = strategy.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                        strategy.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = selectedStatus === null || strategy.status === selectedStatus;
    const matchesAssetClass = selectedAssetClass === null || strategy.assetClass === selectedAssetClass;
    const matchesRiskLevel = selectedRiskLevel === null || strategy.riskLevel === selectedRiskLevel;
    
    return matchesSearch && matchesStatus && matchesAssetClass && matchesRiskLevel;
  });
  
  const clearFilters = () => {
    setSelectedStatus(null);
    setSelectedAssetClass(null);
    setSelectedRiskLevel(null);
  };
  
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between gap-4">
        <h1 className="text-2xl font-bold text-arctic">Strategy Management</h1>
        <Button className="bg-neon-green text-space-blue hover:bg-neon-green/90">
          <PlusCircle size={18} className="mr-2" />
          New Strategy
        </Button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left panel - Filters */}
        <div className="lg:col-span-1 space-y-6">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-arctic/50" size={18} />
            <Input 
              placeholder="Search strategies..." 
              className="pl-10 bg-graphite/30 border-white/10 text-arctic placeholder:text-arctic/50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          
          {/* Filters */}
          <div className="bg-graphite/30 border border-white/10 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-arctic flex items-center">
                <Filter size={16} className="mr-2" />
                Filters
              </h3>
              {(selectedStatus || selectedAssetClass || selectedRiskLevel) && (
                <Button variant="ghost" size="sm" onClick={clearFilters} className="text-xs text-arctic/70">
                  Clear All
                </Button>
              )}
            </div>
            
            {/* Status filters */}
            <div className="mb-4">
              <h4 className="text-xs font-medium text-arctic/70 mb-2">Status</h4>
              <div className="space-y-1">
                {statuses.map(status => (
                  <button
                    key={status}
                    className={`w-full text-left px-3 py-1.5 text-sm rounded-md transition-colors ${
                      selectedStatus === status ? 'bg-neon-green text-space-blue' : 'text-arctic/70 hover:text-arctic hover:bg-white/5'
                    }`}
                    onClick={() => setSelectedStatus(selectedStatus === status ? null : status)}
                  >
                    {status}
                  </button>
                ))}
              </div>
            </div>
            
            {/* Asset Class filters */}
            <div className="mb-4">
              <h4 className="text-xs font-medium text-arctic/70 mb-2">Asset Class</h4>
              <div className="space-y-1">
                {assetClasses.map(assetClass => (
                  <button
                    key={assetClass}
                    className={`w-full text-left px-3 py-1.5 text-sm rounded-md transition-colors ${
                      selectedAssetClass === assetClass ? 'bg-electric-cyan text-space-blue' : 'text-arctic/70 hover:text-arctic hover:bg-white/5'
                    }`}
                    onClick={() => setSelectedAssetClass(selectedAssetClass === assetClass ? null : assetClass)}
                  >
                    {assetClass}
                  </button>
                ))}
              </div>
            </div>
            
            {/* Risk Level filters */}
            <div>
              <h4 className="text-xs font-medium text-arctic/70 mb-2">Risk Level</h4>
              <div className="space-y-1">
                {riskLevels.map(riskLevel => {
                  const riskColors = {
                    Low: 'bg-green-500',
                    Medium: 'bg-caution',
                    High: 'bg-danger'
                  };
                  
                  const color = riskColors[riskLevel as keyof typeof riskColors];
                  
                  return (
                    <button
                      key={riskLevel}
                      className={`w-full text-left px-3 py-1.5 text-sm rounded-md transition-colors flex items-center ${
                        selectedRiskLevel === riskLevel ? `${color} text-space-blue` : 'text-arctic/70 hover:text-arctic hover:bg-white/5'
                      }`}
                      onClick={() => setSelectedRiskLevel(selectedRiskLevel === riskLevel ? null : riskLevel)}
                    >
                      <span className={`inline-block w-2 h-2 rounded-full mr-2 ${color}`}></span>
                      {riskLevel}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
        
        {/* Right panel - Strategy Cards */}
        <div className="lg:col-span-3">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredStrategies.length > 0 ? (
              filteredStrategies.map(strategy => (
                <StrategyCard
                  key={strategy.id}
                  name={strategy.name}
                  description={strategy.description}
                  author={strategy.author}
                  version={strategy.version}
                  lastModified={strategy.lastModified}
                  status={strategy.status}
                  assetClass={strategy.assetClass}
                  riskLevel={strategy.riskLevel}
                  codeSnippet={strategy.codeSnippet}
                />
              ))
            ) : (
              <div className="lg:col-span-2 flex flex-col items-center justify-center p-12 bg-graphite/30 border border-white/10 rounded-lg">
                <div className="h-16 w-16 rounded-full bg-space-blue flex items-center justify-center mb-4">
                  <Search className="h-8 w-8 text-arctic/50" />
                </div>
                <h3 className="text-lg font-medium text-arctic mb-2">No strategies found</h3>
                <p className="text-sm text-arctic/70 text-center">
                  Try adjusting your search or filters to find what you're looking for.
                </p>
                <Button 
                  variant="outline" 
                  className="mt-4 border-white/10 text-arctic/70 hover:text-arctic"
                  onClick={clearFilters}
                >
                  Clear All Filters
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Strategies;
