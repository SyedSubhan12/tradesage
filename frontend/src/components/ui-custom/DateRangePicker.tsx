
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Calendar } from '@/components/ui/calendar';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import { Calendar as CalendarIcon } from 'lucide-react';

export function DateRangePicker() {
  const [date, setDate] = useState<Date | undefined>(new Date());
  const [isOpen, setIsOpen] = useState(false);
  const [activePreset, setActivePreset] = useState("1D");

  const handlePresetClick = (preset: string) => {
    setActivePreset(preset);
    // In a real app, we would calculate the actual date range based on the preset
    setIsOpen(false);
  };

  return (
    <Popover open={isOpen} onOpenChange={setIsOpen}>
      <PopoverTrigger asChild>
        <Button 
          variant="outline" 
          className={cn(
            "justify-start text-left font-normal border-white/10 bg-graphite/30 hover:bg-graphite/50",
            "text-sm text-arctic/90"
          )}
        >
          <CalendarIcon className="mr-2 h-4 w-4" />
          {activePreset}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0 bg-graphite border border-white/10" align="start">
        <div className="grid gap-2 p-3">
          <div className="flex gap-2">
            {["1D", "1W", "1M", "YTD"].map((preset) => (
              <Button
                key={preset}
                variant="outline"
                size="sm"
                className={cn(
                  "border-white/10 bg-space-blue hover:bg-white/5",
                  activePreset === preset && "bg-neon-green text-space-blue hover:bg-neon-green/90"
                )}
                onClick={() => handlePresetClick(preset)}
              >
                {preset}
              </Button>
            ))}
          </div>
        </div>
        <div className="p-3 border-t border-white/10">
          <Calendar
            mode="single"
            selected={date}
            onSelect={(newDate) => {
              setDate(newDate);
              setActivePreset("Custom");
              setIsOpen(false);
            }}
            initialFocus
            className="bg-graphite text-arctic"
          />
        </div>
      </PopoverContent>
    </Popover>
  );
}
