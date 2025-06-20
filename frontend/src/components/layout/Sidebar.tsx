
import React from 'react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { 
  BarChart2, 
  Briefcase, 
  Zap, 
  LineChart, 
  Newspaper, 
  BookOpen, 
  Link as LinkIcon, 
  Settings, 
  ChevronLeft, 
  ChevronRight 
} from 'lucide-react';

interface SidebarProps {
  collapsed: boolean;
  toggleSidebar: () => void;
  className?: string;
}

interface NavItemProps {
  icon: React.ReactNode;
  label: string;
  to: string;
  collapsed: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ icon, label, to, collapsed }) => (
  <Link 
    to={to} 
    className={cn(
      "flex items-center p-3 my-1 rounded-lg transition-all duration-300",
      "text-arctic/70 hover:text-arctic hover:bg-white/5",
      collapsed ? "justify-center" : "justify-start"
    )}
  >
    <div className="flex items-center justify-center w-6 h-6">
      {icon}
    </div>
    {!collapsed && (
      <span className="ml-3 text-sm font-medium">{label}</span>
    )}
  </Link>
);

const Sidebar: React.FC<SidebarProps> = ({ collapsed, toggleSidebar, className }) => {
  return (
    <aside
      className={cn(
        "bg-space-blue border-r border-white/10 transition-all duration-300 z-10",
        collapsed ? "w-20" : "w-64",
        className
      )}
    >
      <div className="flex flex-col h-full">
        {/* Logo and toggle */}
        <div className={cn(
          "flex items-center p-4 border-b border-white/10 h-16",
          collapsed ? "justify-center" : "justify-between"
        )}>
          {!collapsed && (
            <div className="flex items-center">
              <div className="h-8 w-8 rounded-md bg-gradient-to-r from-neon-green to-electric-cyan flex items-center justify-center">
                <BarChart2 className="h-5 w-5 text-space-blue" />
              </div>
              <h1 className="ml-3 text-xl font-bold text-arctic">TradeSage</h1>
            </div>
          )}
          {collapsed && (
            <div className="h-8 w-8 rounded-md bg-gradient-to-r from-neon-green to-electric-cyan flex items-center justify-center">
              <BarChart2 className="h-5 w-5 text-space-blue" />
            </div>
          )}
          <button onClick={toggleSidebar} className="text-arctic/50 hover:text-arctic p-1">
            {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
          </button>
        </div>
        
        {/* Navigation items */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          <NavItem
            to="/"
            icon={<Briefcase size={20} />}
            label="Dashboard"
            collapsed={collapsed}
          />
          <NavItem
            to="/strategies"
            icon={<Zap size={20} />}
            label="Strategies"
            collapsed={collapsed}
          />
          <NavItem
            to="/backtest"
            icon={<LineChart size={20} />}
            label="Backtesting"
            collapsed={collapsed}
          />
          <NavItem
            to="/news"
            icon={<Newspaper size={20} />}
            label="News Analysis"
            collapsed={collapsed}
          />
          <NavItem
            to="/journal"
            icon={<BookOpen size={20} />}
            label="Trade Journal"
            collapsed={collapsed}
          />
          <NavItem
            to="/webhooks"
            icon={<LinkIcon size={20} />}
            label="Webhooks"
            collapsed={collapsed}
          />
          
          <div className="border-t border-white/10 my-4"></div>
          
          <NavItem
            to="/settings"
            icon={<Settings size={20} />}
            label="Settings"
            collapsed={collapsed}
          />
        </nav>
        
        {/* User profile */}
        <div className={cn(
          "p-4 border-t border-white/10",
          "flex items-center",
          collapsed ? "justify-center" : "justify-start"
        )}>
          <div className="h-8 w-8 rounded-full bg-plasma-purple/20 flex items-center justify-center">
            <span className="text-xs font-medium text-plasma-purple">JD</span>
          </div>
          {!collapsed && (
            <div className="ml-3">
              <p className="text-sm font-medium text-arctic">John Doe</p>
              <p className="text-xs text-arctic/50">Pro Trader</p>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
