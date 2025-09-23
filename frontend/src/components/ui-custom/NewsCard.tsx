
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export interface NewsItem {
  headline: string;
  source: string;
  timestamp: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  impactScore: number; // 1-5
  summary: string;
}

interface NewsCardProps {
  item: NewsItem;
}

export function NewsCard({ item }: NewsCardProps) {
  const sentimentEmoji = {
    positive: '😊',
    neutral: '😐',
    negative: '😡'
  };
  
  const sentimentColor = {
    positive: 'text-neon-green',
    neutral: 'text-caution',
    negative: 'text-danger'
  };
  
  // Generate star rating based on impact score
  const renderImpactStars = () => {
    const stars = [];
    for (let i = 0; i < 5; i++) {
      stars.push(
        <span key={i} className={i < item.impactScore ? 'text-caution' : 'text-arctic/20'}>
          ★
        </span>
      );
    }
    return stars;
  };
  
  return (
    <Card className="bg-graphite/30 border-white/10 hover:shadow-md hover:shadow-neon-green/5 transition-all duration-300">
      <CardContent className="p-4">
        <div className="flex justify-between items-start mb-2">
          <Badge variant="outline" className="bg-space-blue border-white/10 text-xs">
            {item.source}
          </Badge>
          <span className="text-xs text-arctic/50">{item.timestamp}</span>
        </div>
        
        <h3 className="text-sm font-medium text-arctic mb-2">{item.headline}</h3>
        
        <div className="flex justify-between items-center mt-3">
          <div className="flex items-center">
            <span className={`text-lg mr-1 ${sentimentColor[item.sentiment]}`}>
              {sentimentEmoji[item.sentiment]}
            </span>
            <span className="text-xs text-arctic/70">
              {item.sentiment.charAt(0).toUpperCase() + item.sentiment.slice(1)}
            </span>
          </div>
          
          <div className="flex text-xs">
            <span className="mr-1">Impact:</span>
            {renderImpactStars()}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
