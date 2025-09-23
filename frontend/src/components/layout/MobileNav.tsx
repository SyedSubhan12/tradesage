
import React from 'react';
import { Link } from 'react-router-dom';
import { X, BarChart2, Briefcase, Zap, LineChart, Newspaper, BookOpen, Link as LinkIcon, Settings } from 'lucide-react';

interface MobileNavProps {
  open: boolean;
  onClose: () => void;
}

const MobileNav: React.FC<MobileNavProps> = ({ open, onClose }) => {
  if (!open) return null;
  
  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm md:hidden">
      <div className="fixed inset-y-0 left-0 w-80 bg-space-blue overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-white/10">
          <div className="flex items-center">
            <div className="h-8 w-8 rounded-md bg-gradient-to-r from-neon-green to-electric-cyan flex items-center justify-center">
              <BarChart2 className="h-5 w-5 text-space-blue" />
            </div>
            <h1 className="ml-3 text-xl font-bold text-arctic">TradeSage</h1>
          </div>
          <button onClick={onClose} className="p-1 text-arctic/70 hover:text-arctic">
            <X size={20} />
          </button>
        </div>
        
        <nav className="p-4">
          <Link to="/" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <Briefcase size={20} />
            <span className="ml-3 text-sm font-medium">Dashboard</span>
          </Link>
          
          <Link to="/strategies" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <Zap size={20} />
            <span className="ml-3 text-sm font-medium">Strategies</span>
          </Link>
          
          <Link to="/backtest" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <LineChart size={20} />
            <span className="ml-3 text-sm font-medium">Backtesting</span>
          </Link>
          
          <Link to="/news" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <Newspaper size={20} />
            <span className="ml-3 text-sm font-medium">News Analysis</span>
          </Link>
          
          <Link to="/journal" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <BookOpen size={20} />
            <span className="ml-3 text-sm font-medium">Trade Journal</span>
          </Link>
          
          <Link to="/webhooks" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <LinkIcon size={20} />
            <span className="ml-3 text-sm font-medium">Webhooks</span>
          </Link>
          
          <div className="border-t border-white/10 my-4"></div>
          
          <Link to="/settings" onClick={onClose} className="flex items-center p-3 my-1 rounded-lg text-arctic/70 hover:text-arctic hover:bg-white/5">
            <Settings size={20} />
            <span className="ml-3 text-sm font-medium">Settings</span>
          </Link>
        </nav>
        
        <div className="p-4 border-t border-white/10 absolute bottom-0 w-full">
          <div className="flex items-center">
            <div className="h-8 w-8 rounded-full bg-plasma-purple/20 flex items-center justify-center">
              <span className="text-xs font-medium text-plasma-purple">JD</span>
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-arctic">John Doe</p>
              <p className="text-xs text-arctic/50">Pro Trader</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export { MobileNav };
