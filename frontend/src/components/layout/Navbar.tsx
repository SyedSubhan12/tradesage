
import React, { useState } from 'react';
import { Menu, Search, Bell } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DateRangePicker } from '../ui-custom/DateRangePicker';
import { MobileNav } from './MobileNav';

interface NavbarProps {
  toggleSidebar: () => void;
  sidebarCollapsed: boolean;
}

const Navbar: React.FC<NavbarProps> = ({ toggleSidebar, sidebarCollapsed }) => {
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);
  
  return (
    <header className="h-16 border-b border-white/10 bg-space-blue flex items-center px-4 md:px-6">
      <div className="md:hidden">
        <Button variant="ghost" size="icon" onClick={() => setIsMobileNavOpen(true)}>
          <Menu className="h-6 w-6 text-arctic" />
        </Button>
        <MobileNav open={isMobileNavOpen} onClose={() => setIsMobileNavOpen(false)} />
      </div>
      
      <div className="hidden md:block">
        <Button variant="ghost" size="icon" onClick={toggleSidebar} className="mr-2">
          <Menu className="h-5 w-5 text-arctic" />
        </Button>
      </div>
      
      <div className="flex items-center gap-2 ml-auto">
        <div className="hidden md:block">
          <DateRangePicker />
        </div>
        
        <div className="relative">
          <Button variant="ghost" size="icon" className="text-arctic/70 hover:text-arctic">
            <Search className="h-5 w-5" />
          </Button>
        </div>
        
        <div className="relative">
          <Button variant="ghost" size="icon" className="text-arctic/70 hover:text-arctic">
            <Bell className="h-5 w-5" />
            <span className="absolute top-1 right-1.5 h-2 w-2 rounded-full bg-neon-green"></span>
          </Button>
        </div>
        
        <div className="hidden md:flex items-center ml-4 gap-3">
          <div className="h-8 w-8 rounded-full bg-plasma-purple/20 flex items-center justify-center">
            <span className="text-xs font-medium text-plasma-purple">JD</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
