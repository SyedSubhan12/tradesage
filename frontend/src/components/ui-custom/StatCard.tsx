
import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  className?: string;
}

export function StatCard({ title, value, icon, trend, className }: StatCardProps) {
  return (
    <Card className={cn("bg-graphite/30 border-white/10", className)}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-arctic/70">{title}</CardTitle>
        {icon && <div className="text-arctic/70">{icon}</div>}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold text-arctic">{value}</div>
        {trend && (
          <div className="flex items-center mt-1">
            <span className={cn(
              "text-xs",
              trend.isPositive ? "text-neon-green" : "text-danger"
            )}>
              {trend.isPositive ? '+' : ''}{trend.value}%
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
