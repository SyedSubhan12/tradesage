
import React, { useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

// Mock data for the chart
const mockData = [
  { date: '2023-01-01', value: 100 },
  { date: '2023-02-01', value: 120 },
  { date: '2023-03-01', value: 110 },
  { date: '2023-04-01', value: 140 },
  { date: '2023-05-01', value: 135 },
  { date: '2023-06-01', value: 160 },
  { date: '2023-07-01', value: 170 },
  { date: '2023-08-01', value: 190 },
  { date: '2023-09-01', value: 200 },
  { date: '2023-10-01', value: 220 },
];

interface PerformanceChartProps {
  title: string;
  height?: number;
}

export function PerformanceChart({ title, height = 240 }: PerformanceChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    // Simple canvas drawing for a line chart
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Set up chart dimensions
    const padding = 20;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;
    
    // Find min/max values
    const maxValue = Math.max(...mockData.map(d => d.value));
    const minValue = Math.min(...mockData.map(d => d.value));
    const valueRange = maxValue - minValue;
    
    // Draw gradient background
    const gradient = ctx.createLinearGradient(0, padding, 0, chartHeight + padding);
    gradient.addColorStop(0, 'rgba(0, 255, 157, 0.2)');
    gradient.addColorStop(1, 'rgba(0, 255, 157, 0)');
    
    // Draw line and fill
    ctx.beginPath();
    mockData.forEach((data, i) => {
      const x = padding + (i / (mockData.length - 1)) * chartWidth;
      const y = padding + chartHeight - ((data.value - minValue) / valueRange) * chartHeight;
      
      if (i === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });
    
    // Draw line
    ctx.strokeStyle = '#00FF9D';
    ctx.lineWidth = 2;
    ctx.stroke();
    
    // Fill area under line
    ctx.lineTo(padding + chartWidth, padding + chartHeight);
    ctx.lineTo(padding, padding + chartHeight);
    ctx.fillStyle = gradient;
    ctx.fill();
    
  }, []);
  
  return (
    <Card className="bg-graphite/30 border-white/10">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-arctic/70">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="w-full" style={{ height }}>
          <canvas
            ref={canvasRef}
            width={800}
            height={height}
            className="w-full h-full"
          />
        </div>
      </CardContent>
    </Card>
  );
}
