
import React, { useState } from 'react';
import Sidebar from './Sidebar';
import Navbar from './Navbar';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  
  const toggleSidebar = () => {
    setSidebarCollapsed(prev => !prev);
  };

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Sidebar for desktop */}
      <Sidebar collapsed={sidebarCollapsed} toggleSidebar={toggleSidebar} className="hidden md:block" />
      
      <div className="flex-1 flex flex-col min-h-screen max-h-screen overflow-hidden">
        {/* Top navbar */}
        <Navbar toggleSidebar={toggleSidebar} sidebarCollapsed={sidebarCollapsed} />
        
        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export default MainLayout;
