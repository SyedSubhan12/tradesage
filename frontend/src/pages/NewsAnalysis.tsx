
import React, { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Search, Filter, RefreshCw, ExternalLink } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Slider } from '@/components/ui/slider';

// Mock news data
const mockNewsItems = [
  {
    id: '1',
    timestamp: '2023-10-21 09:30',
    headline: 'Fed signals potential rate cut in upcoming meeting',
    content: 'The Federal Reserve has signaled that it may cut interest rates in the upcoming FOMC meeting, citing improving inflation data and concerns about the labor market.',
    source: 'Bloomberg',
    sourceImg: '/placeholder.svg',
    symbols: ['SPY', 'TLT', 'GLD'],
    sentiment: 'positive',
    impactScore: 8
  },
  {
    id: '2',
    timestamp: '2023-10-21 10:15',
    headline: 'NVIDIA reports record quarterly revenue on AI chip demand',
    content: 'NVIDIA has reported record quarterly revenue, driven by unprecedented demand for its AI chips. The company has raised its future guidance.',
    source: 'CNBC',
    sourceImg: '/placeholder.svg',
    symbols: ['NVDA', 'AMD', 'SOXX'],
    sentiment: 'positive',
    impactScore: 9
  },
  {
    id: '3',
    timestamp: '2023-10-21 11:20',
    headline: 'Oil prices fall amid concerns over global demand',
    content: 'Oil prices have fallen by 2% as concerns over global demand persist, with China\'s economic slowdown being a key factor.',
    source: 'Reuters',
    sourceImg: '/placeholder.svg',
    symbols: ['USO', 'XLE', 'XOM'],
    sentiment: 'negative',
    impactScore: 6
  },
  {
    id: '4',
    timestamp: '2023-10-21 12:05',
    headline: 'Apple unveils new MacBook lineup with enhanced AI capabilities',
    content: 'Apple has announced a new lineup of MacBooks featuring enhanced AI capabilities powered by the latest M3 chips, aiming to capture the growing demand for AI-capable hardware.',
    source: 'TechCrunch',
    sourceImg: '/placeholder.svg',
    symbols: ['AAPL', 'MSFT'],
    sentiment: 'positive',
    impactScore: 7
  },
  {
    id: '5',
    timestamp: '2023-10-21 13:15',
    headline: 'Treasury yields stabilize after recent volatility',
    content: 'Treasury yields have stabilized following a period of significant volatility, as investors reassess economic data and Fed statements.',
    source: 'WSJ',
    sourceImg: '/placeholder.svg',
    symbols: ['TLT', 'IEF', 'SHY'],
    sentiment: 'neutral',
    impactScore: 5
  },
  {
    id: '6',
    timestamp: '2023-10-21 14:30',
    headline: 'European markets close higher on positive earnings reports',
    content: 'European stock markets closed higher today, buoyed by positive earnings reports from several major companies, particularly in the technology and financial sectors.',
    source: 'Financial Times',
    sourceImg: '/placeholder.svg',
    symbols: ['VGK', 'EZU', 'EUFN'],
    sentiment: 'positive',
    impactScore: 6
  },
  {
    id: '7',
    timestamp: '2023-10-21 15:45',
    headline: 'Bitcoin breaks above $60,000 on increased institutional adoption',
    content: 'Bitcoin has surged above $60,000 for the first time in weeks, driven by reports of increased institutional adoption and favorable regulatory developments.',
    source: 'CoinDesk',
    sourceImg: '/placeholder.svg',
    symbols: ['BTC', 'COIN', 'MSTR'],
    sentiment: 'positive',
    impactScore: 8
  }
];

const NewsAnalysis = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSentiment, setSelectedSentiment] = useState<string | null>(null);
  const [selectedSymbols, setSelectedSymbols] = useState<string[]>([]);
  const [impactRange, setImpactRange] = useState<[number, number]>([0, 10]);
  
  // Get unique symbols and sentiments
  const allSymbols = Array.from(new Set(mockNewsItems.flatMap(item => item.symbols))).sort();
  const sentiments = ['positive', 'neutral', 'negative'];
  
  // Filter news items
  const filteredNews = mockNewsItems.filter(item => {
    const matchesSearch = item.headline.toLowerCase().includes(searchTerm.toLowerCase()) ||
                        item.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
                        item.source.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSentiment = selectedSentiment === null || item.sentiment === selectedSentiment;
    const matchesSymbols = selectedSymbols.length === 0 || 
                           item.symbols.some(symbol => selectedSymbols.includes(symbol));
    const matchesImpact = item.impactScore >= impactRange[0] && item.impactScore <= impactRange[1];
    
    return matchesSearch && matchesSentiment && matchesSymbols && matchesImpact;
  });
  
  const toggleSymbol = (symbol: string) => {
    if (selectedSymbols.includes(symbol)) {
      setSelectedSymbols(selectedSymbols.filter(s => s !== symbol));
    } else {
      setSelectedSymbols([...selectedSymbols, symbol]);
    }
  };
  
  const clearFilters = () => {
    setSelectedSentiment(null);
    setSelectedSymbols([]);
    setImpactRange([0, 10]);
  };
  
  const getSentimentEmoji = (sentiment: string) => {
    switch (sentiment) {
      case 'positive': return '😊';
      case 'neutral': return '😐';
      case 'negative': return '😡';
      default: return '';
    }
  };
  
  const getSentimentColor = (sentiment: string) => {
    switch (sentiment) {
      case 'positive': return 'text-neon-green';
      case 'neutral': return 'text-caution';
      case 'negative': return 'text-danger';
      default: return '';
    }
  };
  
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between gap-4">
        <h1 className="text-2xl font-bold text-arctic">AI News Analysis</h1>
        <Button 
          variant="outline" 
          className="border-white/10 bg-graphite/30 text-arctic/70 hover:text-arctic flex items-center"
        >
          <RefreshCw size={16} className="mr-2" />
          Refresh News
        </Button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left panel - Filters */}
        <div className="lg:col-span-1 space-y-6">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-arctic/50" size={18} />
            <Input 
              placeholder="Search news..." 
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
              {(selectedSentiment || selectedSymbols.length > 0 || impactRange[0] > 0 || impactRange[1] < 10) && (
                <Button variant="ghost" size="sm" onClick={clearFilters} className="text-xs text-arctic/70">
                  Clear All
                </Button>
              )}
            </div>
            
            {/* Sentiment filters */}
            <div className="mb-6">
              <h4 className="text-xs font-medium text-arctic/70 mb-3">Sentiment</h4>
              <div className="flex gap-2">
                {sentiments.map(sentiment => (
                  <Button
                    key={sentiment}
                    variant="outline"
                    size="sm"
                    className={`border-white/10 ${
                      selectedSentiment === sentiment 
                        ? `bg-${sentiment === 'positive' ? 'neon-green' : sentiment === 'neutral' ? 'caution' : 'danger'} text-space-blue` 
                        : 'text-arctic/70 hover:text-arctic hover:bg-white/5'
                    } flex-1`}
                    onClick={() => setSelectedSentiment(selectedSentiment === sentiment ? null : sentiment)}
                  >
                    <span className="mr-1">{getSentimentEmoji(sentiment)}</span>
                    {sentiment.charAt(0).toUpperCase() + sentiment.slice(1)}
                  </Button>
                ))}
              </div>
            </div>
            
            {/* Impact score range */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-medium text-arctic/70">Impact Score</h4>
                <span className="text-xs text-arctic/70">
                  {impactRange[0]} - {impactRange[1]}
                </span>
              </div>
              <Slider 
                defaultValue={[0, 10]} 
                min={0} 
                max={10} 
                step={1} 
                value={impactRange}
                onValueChange={(value) => setImpactRange(value as [number, number])}
                className="my-4"
              />
            </div>
            
            {/* Symbols tag cloud */}
            <div>
              <h4 className="text-xs font-medium text-arctic/70 mb-3">Symbols</h4>
              <div className="flex flex-wrap gap-2">
                {allSymbols.map(symbol => (
                  <Badge
                    key={symbol}
                    variant="outline"
                    className={`cursor-pointer ${
                      selectedSymbols.includes(symbol) 
                        ? 'bg-electric-cyan text-space-blue border-electric-cyan' 
                        : 'bg-space-blue text-arctic/70 border-white/10 hover:bg-white/5'
                    }`}
                    onClick={() => toggleSymbol(symbol)}
                  >
                    {symbol}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        </div>
        
        {/* Right panel - News Table */}
        <div className="lg:col-span-3">
          <Card className="bg-graphite/30 border-white/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-arctic/70">News Articles</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader className="bg-space-blue">
                  <TableRow className="hover:bg-transparent border-white/10">
                    <TableHead className="text-arctic/70 w-32">Timestamp</TableHead>
                    <TableHead className="text-arctic/70">Headline</TableHead>
                    <TableHead className="text-arctic/70 w-24">Source</TableHead>
                    <TableHead className="text-arctic/70 w-28">Sentiment</TableHead>
                    <TableHead className="text-arctic/70 w-28">Impact Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredNews.length > 0 ? (
                    filteredNews.map(item => (
                      <TableRow key={item.id} className="border-white/10 hover:bg-white/5 cursor-pointer">
                        <TableCell className="text-xs text-arctic/70">{item.timestamp}</TableCell>
                        <TableCell>
                          <div>
                            <p className="text-sm text-arctic font-medium">{item.headline}</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {item.symbols.map(symbol => (
                                <Badge key={symbol} variant="outline" className="bg-space-blue border-white/10 text-xs">
                                  {symbol}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center">
                            <div className="h-6 w-6 rounded bg-space-blue flex items-center justify-center mr-2">
                              <img src={item.sourceImg} alt={item.source} className="h-4 w-4" />
                            </div>
                            <span className="text-xs text-arctic/70">{item.source}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center">
                            <span className={`text-lg mr-2 ${getSentimentColor(item.sentiment)}`}>
                              {getSentimentEmoji(item.sentiment)}
                            </span>
                            <span className="text-xs capitalize text-arctic/70">{item.sentiment}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center">
                            <div className="w-full bg-space-blue rounded-full h-1 mr-2">
                              <div 
                                className={`h-1 rounded-full ${
                                  item.sentiment === 'positive' ? 'bg-neon-green' : 
                                  item.sentiment === 'negative' ? 'bg-danger' : 'bg-caution'
                                }`}
                                style={{ width: `${item.impactScore * 10}%` }}
                              />
                            </div>
                            <span className="text-sm font-medium text-arctic">{item.impactScore}</span>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center">
                        <div className="flex flex-col items-center justify-center">
                          <Search className="h-8 w-8 text-arctic/50 mb-2" />
                          <p className="text-sm text-arctic/70">No news articles found</p>
                          <Button 
                            variant="outline" 
                            size="sm"
                            className="mt-2 border-white/10"
                            onClick={clearFilters}
                          >
                            Clear Filters
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default NewsAnalysis;
