
import React, { useState } from 'react';
import { X, Search, Plus } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Button } from '@/components/ui/button';

interface Asset {
  id: string;
  name: string;
  type: string;
}

interface MultiAssetSelectorProps {
  assets: Asset[];
  selectedAssets: string[];
  onSelectAssets: (assets: string[]) => void;
}

export const MultiAssetSelector: React.FC<MultiAssetSelectorProps> = ({
  assets,
  selectedAssets,
  onSelectAssets
}) => {
  const [open, setOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  
  const handleToggleAsset = (assetId: string) => {
    if (selectedAssets.includes(assetId)) {
      onSelectAssets(selectedAssets.filter(id => id !== assetId));
    } else {
      onSelectAssets([...selectedAssets, assetId]);
    }
  };
  
  const handleRemoveAsset = (assetId: string) => {
    onSelectAssets(selectedAssets.filter(id => id !== assetId));
  };
  
  const filteredAssets = searchQuery 
    ? assets.filter(asset => 
        asset.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
        asset.id.toLowerCase().includes(searchQuery.toLowerCase()))
    : assets;
    
  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <label className="text-xs text-arctic/70">Assets</label>
        <span className="text-xs text-arctic/50">{selectedAssets.length} selected</span>
      </div>
      
      <div className="relative">
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <Button 
              variant="outline" 
              className="w-full justify-start border-white/10 bg-space-blue text-sm text-arctic"
            >
              <Plus size={16} className="mr-2" />
              Add assets
            </Button>
          </PopoverTrigger>
          <PopoverContent align="start" className="w-64 p-0 bg-graphite border-white/10">
            <Command>
              <CommandInput placeholder="Search assets..." onValueChange={setSearchQuery} />
              <CommandList>
                <CommandEmpty>No assets found.</CommandEmpty>
                <CommandGroup>
                  {filteredAssets.map((asset) => {
                    const isSelected = selectedAssets.includes(asset.id);
                    return (
                      <CommandItem
                        key={asset.id}
                        onSelect={() => handleToggleAsset(asset.id)}
                        className="flex items-center justify-between cursor-pointer"
                      >
                        <div className="flex flex-col">
                          <span className={isSelected ? "text-neon-green" : "text-arctic"}>{asset.id}</span>
                          <span className="text-xs text-arctic/50">{asset.name}</span>
                        </div>
                        <Badge variant="outline" className="bg-space-blue/50 border-white/10 text-arctic/70">
                          {asset.type}
                        </Badge>
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
      </div>
      
      {selectedAssets.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-3">
          {selectedAssets.map(assetId => {
            const asset = assets.find(a => a.id === assetId);
            if (!asset) return null;
            
            return (
              <Badge 
                key={asset.id}
                variant="secondary"
                className="bg-electric-cyan/10 text-electric-cyan hover:bg-electric-cyan/20 flex items-center gap-1"
              >
                {asset.id}
                <button
                  className="ml-1 rounded-full hover:bg-white/10 p-0.5"
                  onClick={() => handleRemoveAsset(asset.id)}
                >
                  <X size={12} />
                </button>
              </Badge>
            );
          })}
        </div>
      )}
    </div>
  );
};
