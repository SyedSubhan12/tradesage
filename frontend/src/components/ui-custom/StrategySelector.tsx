
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Check, ChevronDown, Code } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Strategy {
  id: string;
  name: string;
  version: string;
  author: string;
}

interface StrategySelectorProps {
  strategies: Strategy[];
  selectedStrategy: string | null;
  onSelectStrategy: (id: string) => void;
}

export const StrategySelector: React.FC<StrategySelectorProps> = ({ 
  strategies, 
  selectedStrategy, 
  onSelectStrategy 
}) => {
  const [open, setOpen] = useState(false);
  
  const selectedStrategyData = selectedStrategy 
    ? strategies.find(s => s.id === selectedStrategy) 
    : null;

  return (
    <div className="space-y-2">
      <label className="text-xs text-arctic/70">Strategy</label>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="w-full justify-between border-white/10 bg-space-blue text-sm text-arctic"
          >
            {selectedStrategyData ? (
              <div className="flex items-center">
                <Code size={16} className="mr-2 text-electric-cyan" />
                <span>{selectedStrategyData.name}</span>
              </div>
            ) : (
              "Select a strategy..."
            )}
            <ChevronDown size={16} className="ml-2 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-full p-0 bg-graphite border-white/10">
          <Command>
            <CommandInput placeholder="Search strategy..." className="h-9" />
            <CommandList>
              <CommandEmpty>No strategy found.</CommandEmpty>
              <CommandGroup>
                {strategies.map((strategy) => (
                  <CommandItem
                    key={strategy.id}
                    value={strategy.name}
                    onSelect={() => {
                      onSelectStrategy(strategy.id);
                      setOpen(false);
                    }}
                    className="flex items-center justify-between"
                  >
                    <div className="flex flex-col">
                      <span className="text-arctic">{strategy.name}</span>
                      <span className="text-xs text-arctic/50">v{strategy.version} • by {strategy.author}</span>
                    </div>
                    <Check
                      className={cn(
                        "ml-2 h-4 w-4",
                        selectedStrategy === strategy.id
                          ? "opacity-100 text-neon-green"
                          : "opacity-0"
                      )}
                    />
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  );
};
