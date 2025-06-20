
import React from 'react';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Zap, Edit2, Trash2 } from 'lucide-react';

interface StrategyCardProps {
  name: string;
  description: string;
  author: string;
  version: string;
  lastModified: string;
  status: 'Active' | 'Backtesting' | 'Paused';
  assetClass: string;
  riskLevel: 'Low' | 'Medium' | 'High';
  codeSnippet: string;
}

export function StrategyCard({
  name,
  description,
  author,
  version,
  lastModified,
  status,
  assetClass,
  riskLevel,
  codeSnippet
}: StrategyCardProps) {
  const statusColors = {
    Active: 'bg-neon-green text-space-blue',
    Backtesting: 'bg-caution text-space-blue',
    Paused: 'bg-graphite text-arctic/70'
  };
  
  const riskColors = {
    Low: 'border-green-500 text-green-500',
    Medium: 'border-caution text-caution',
    High: 'border-danger text-danger'
  };
  
  return (
    <Card className="bg-graphite/30 border-white/10 overflow-hidden hover:shadow-md hover:shadow-neon-green/5 transition-all duration-300">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="text-arctic">{name}</CardTitle>
            <p className="text-xs text-arctic/50 mt-1">by {author} • v{version}</p>
          </div>
          <Badge variant="outline" className={statusColors[status]}>
            {status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-sm text-arctic/70">{description}</div>
        
        <div className="relative bg-space-blue rounded-md p-3 overflow-hidden">
          <pre className="text-xs text-arctic/70 overflow-x-auto max-h-24">
            <code>{codeSnippet}</code>
          </pre>
          <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-space-blue to-transparent"></div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="secondary" className="bg-electric-cyan/10 text-electric-cyan hover:bg-electric-cyan/20">
            {assetClass}
          </Badge>
          <Badge variant="outline" className={`border ${riskColors[riskLevel]}`}>
            {riskLevel} Risk
          </Badge>
        </div>
      </CardContent>
      <CardFooter className="pt-2 flex justify-between border-t border-white/10">
        <div className="text-xs text-arctic/50">Last modified: {lastModified}</div>
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" className="text-arctic/70 hover:text-arctic">
            <Edit2 size={16} />
          </Button>
          <Button size="sm" variant="ghost" className="text-arctic/70 hover:text-danger">
            <Trash2 size={16} />
          </Button>
          <Button size="sm" className="bg-neon-green text-space-blue hover:bg-neon-green/90">
            <Zap size={16} className="mr-1" />
            Run
          </Button>
        </div>
      </CardFooter>
    </Card>
  );
}
