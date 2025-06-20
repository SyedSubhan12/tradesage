
import React from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export interface Signal {
  id: string;
  timestamp: string;
  asset: string;
  type: 'BUY' | 'SELL';
  confidence: number; // 0-100
  status: 'Live' | 'Paused';
}

interface SignalTableProps {
  signals: Signal[];
  onRowClick?: (signal: Signal) => void;
}

export function SignalTable({ signals, onRowClick }: SignalTableProps) {
  return (
    <div className="rounded-md border border-white/10 overflow-hidden">
      <Table>
        <TableHeader className="bg-space-blue">
          <TableRow className="hover:bg-transparent border-white/10">
            <TableHead className="text-arctic/70">Timestamp</TableHead>
            <TableHead className="text-arctic/70">Asset</TableHead>
            <TableHead className="text-arctic/70">Signal</TableHead>
            <TableHead className="text-arctic/70">Confidence</TableHead>
            <TableHead className="text-arctic/70">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {signals.map((signal) => (
            <TableRow 
              key={signal.id} 
              className="border-white/10 hover:bg-white/5 cursor-pointer"
              onClick={() => onRowClick?.(signal)}
            >
              <TableCell className="text-sm text-arctic/70">{signal.timestamp}</TableCell>
              <TableCell className="font-medium text-arctic">{signal.asset}</TableCell>
              <TableCell>
                <span className={signal.type === 'BUY' ? 'text-neon-green' : 'text-danger'}>
                  {signal.type}
                </span>
              </TableCell>
              <TableCell>
                <div className="w-full bg-space-blue rounded-full h-2 mr-2">
                  <div 
                    className={`h-2 rounded-full ${signal.type === 'BUY' ? 'bg-neon-green' : 'bg-danger'}`} 
                    style={{ width: `${signal.confidence}%` }}
                  />
                </div>
              </TableCell>
              <TableCell>
                <span className="flex items-center">
                  <span 
                    className={`inline-block w-2 h-2 rounded-full mr-2 ${
                      signal.status === 'Live' ? 'bg-neon-green' : 'bg-caution'
                    }`}
                  />
                  {signal.status}
                </span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
