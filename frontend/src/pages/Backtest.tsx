
import React, { useState } from 'react';
import { ChevronDown, Layers, Settings, Download, Maximize2, Zap } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Slider } from '@/components/ui/slider';
import { BacktestChart } from '@/components/ui-custom/BacktestChart';
import { BacktestMetrics } from '@/components/ui-custom/BacktestMetrics';
import { StrategySelector } from '@/components/ui-custom/StrategySelector';
import { MultiAssetSelector } from '@/components/ui-custom/MultiAssetSelector';
import { toast } from 'sonner';

// Mock data for strategies
const mockStrategies = [
  { id: '1', name: 'Mean Reversion ETF Strategy', version: '1.3.0', author: 'John Doe' },
  { id: '2', name: 'Momentum Breakout Detection', version: '2.1.0', author: 'Jane Smith' },
  { id: '3', name: 'Pairs Trading Strategy', version: '1.0.5', author: 'Michael Lee' },
  { id: '4', name: 'Trend-Following SMA Crossover', version: '3.2.1', author: 'Sarah Johnson' },
];

// Mock data for assets
const mockAssets = [
  { id: 'AAPL', name: 'Apple Inc.', type: 'Equity' },
  { id: 'TSLA', name: 'Tesla Inc.', type: 'Equity' },
  { id: 'BTC', name: 'Bitcoin', type: 'Crypto' },
  { id: 'EUR/USD', name: 'Euro/US Dollar', type: 'Forex' },
  { id: '/ES', name: 'E-mini S&P 500', type: 'Futures' },
  { id: 'XLE', name: 'Energy Select Sector SPDR', type: 'ETF' },
];

// Mock initial configuration for the backtest
const initialConfig = {
  initialCapital: 100000,
  positionSizing: 5, // percentage
  slippage: 0.05, // 5 basis points
  commission: 0.1, // 0.1% commission per trade
};

const Backtest = () => {
  const [selectedStrategy, setSelectedStrategy] = useState<string | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [config, setConfig] = useState(initialConfig);
  const [isRunning, setIsRunning] = useState(false);
  const [showAdvancedSettings, setShowAdvancedSettings] = useState(false);
  const [activeLayers, setActiveLayers] = useState({
    signals: true,
    news: false,
    volume: true,
    cot: false,
  });

  const toggleLayer = (layer: keyof typeof activeLayers) => {
    setActiveLayers((prev) => ({
      ...prev,
      [layer]: !prev[layer],
    }));
  };

  const handleRunBacktest = () => {
    if (!selectedStrategy) {
      toast.error("Please select a strategy");
      return;
    }

    if (selectedAssets.length === 0) {
      toast.error("Please select at least one asset");
      return;
    }

    setIsRunning(true);
    toast.info("Starting backtest simulation...");
    
    // Simulate backtest running
    setTimeout(() => {
      setIsRunning(false);
      toast.success("Backtest completed successfully!");
    }, 3000);
  };

  const handleExport = (format: string) => {
    toast.success(`Exporting results as ${format}...`);
  };

  const handleCapitalChange = (value: number[]) => {
    setConfig(prev => ({
      ...prev,
      initialCapital: value[0]
    }));
  };

  const handlePositionSizingChange = (value: number[]) => {
    setConfig(prev => ({
      ...prev,
      positionSizing: value[0]
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between gap-4">
        <h1 className="text-2xl font-bold text-arctic">Strategy Backtesting</h1>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            className="border-white/10 bg-graphite/30 text-arctic/70 hover:text-arctic"
            onClick={() => handleExport('CSV')}
          >
            <Download size={18} className="mr-2" />
            Export Results
          </Button>
          <Button 
            className="bg-neon-green text-space-blue hover:bg-neon-green/90"
            onClick={handleRunBacktest}
            disabled={isRunning}
          >
            <Zap size={18} className="mr-2" />
            {isRunning ? 'Running...' : 'Run Backtest'}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Panel - Parameters */}
        <div className="lg:col-span-1 space-y-6">
          <Card className="bg-graphite/30 border-white/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-arctic/70">Strategy Selection</CardTitle>
            </CardHeader>
            <CardContent className="p-4 space-y-6">
              <StrategySelector 
                strategies={mockStrategies}
                selectedStrategy={selectedStrategy}
                onSelectStrategy={setSelectedStrategy}
              />
              
              <MultiAssetSelector 
                assets={mockAssets}
                selectedAssets={selectedAssets}
                onSelectAssets={setSelectedAssets}
              />
            </CardContent>
          </Card>

          <Card className="bg-graphite/30 border-white/10">
            <CardHeader className="pb-2 flex justify-between items-center">
              <CardTitle className="text-sm font-medium text-arctic/70">Capital Settings</CardTitle>
              <Button 
                variant="ghost" 
                size="sm" 
                className="h-8 w-8 p-0 text-arctic/70"
                onClick={() => setShowAdvancedSettings(!showAdvancedSettings)}
              >
                <Settings size={16} />
              </Button>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Initial Capital</span>
                  <span className="text-xs font-medium text-arctic">${config.initialCapital.toLocaleString()}</span>
                </div>
                <Slider
                  defaultValue={[config.initialCapital]}
                  min={10000}
                  max={1000000}
                  step={10000}
                  onValueChange={handleCapitalChange}
                />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-xs text-arctic/70">Position Sizing (%)</span>
                  <span className="text-xs font-medium text-arctic">{config.positionSizing}%</span>
                </div>
                <Slider
                  defaultValue={[config.positionSizing]}
                  min={1}
                  max={100}
                  step={1}
                  onValueChange={handlePositionSizingChange}
                />
              </div>
              
              {showAdvancedSettings && (
                <div className="space-y-4 pt-4 border-t border-white/10 animate-fade-in">
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-xs text-arctic/70">Slippage (bps)</span>
                      <span className="text-xs font-medium text-arctic">{config.slippage * 100}</span>
                    </div>
                    <Slider
                      defaultValue={[config.slippage * 100]}
                      min={0}
                      max={10}
                      step={0.5}
                      onValueChange={(value) => setConfig(prev => ({ ...prev, slippage: value[0] / 100 }))}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-xs text-arctic/70">Commission (%)</span>
                      <span className="text-xs font-medium text-arctic">{config.commission}%</span>
                    </div>
                    <Slider
                      defaultValue={[config.commission]}
                      min={0}
                      max={2}
                      step={0.05}
                      onValueChange={(value) => setConfig(prev => ({ ...prev, commission: value[0] }))}
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
        
        {/* Main Content - Chart and Metrics */}
        <div className="lg:col-span-3 space-y-6">
          {/* Chart Controls */}
          <div className="flex justify-between items-center">
            <Tabs defaultValue="1D" className="w-auto">
              <TabsList className="bg-graphite/30 border border-white/10">
                <TabsTrigger value="1H" className="data-[state=active]:bg-white/10">1H</TabsTrigger>
                <TabsTrigger value="4H" className="data-[state=active]:bg-white/10">4H</TabsTrigger>
                <TabsTrigger value="1D" className="data-[state=active]:bg-white/10">1D</TabsTrigger>
                <TabsTrigger value="1W" className="data-[state=active]:bg-white/10">1W</TabsTrigger>
                <TabsTrigger value="1M" className="data-[state=active]:bg-white/10">1M</TabsTrigger>
              </TabsList>
            </Tabs>
            
            <div className="flex items-center gap-2">
              <Button 
                variant="outline" 
                size="sm"
                className="border-white/10 bg-graphite/30 text-arctic/70 hover:text-arctic"
                onClick={() => {}}
              >
                <Layers size={16} className="mr-2" />
                Layers
                <ChevronDown size={14} className="ml-1" />
              </Button>
              
              <Button 
                variant="outline" 
                size="sm"
                className="border-white/10 bg-graphite/30 text-arctic/70 hover:text-arctic"
                onClick={() => {}}
              >
                <Maximize2 size={16} />
              </Button>
            </div>
          </div>
          
          {/* Chart */}
          <Card className="bg-graphite/30 border-white/10 overflow-hidden">
            <CardContent className="p-0">
              <BacktestChart height={400} activeLayers={activeLayers} />
            </CardContent>
          </Card>
          
          {/* Metrics */}
          <BacktestMetrics />
        </div>
      </div>
    </div>
  );
};

export default Backtest;
