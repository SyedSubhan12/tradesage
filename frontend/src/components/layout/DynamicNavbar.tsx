import React, { useEffect, useState } from 'react';
import { ExpandableTabs } from '@/components/ui/expandable-tabs';
import { Home, Zap, DollarSign, Phone } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Link } from 'react-router-dom';
import { useAuth } from '@/lib/authContext';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { UserCircle } from 'lucide-react';

import type { LucideIcon } from 'lucide-react';

type NavTabItem = { title: string; icon: LucideIcon } | { type: 'separator' };

interface DynamicNavbarProps {
  items?: NavTabItem[];
  className?: string;
  onChange?: (index: number | null) => void;
}

const DynamicNavbar: React.FC<DynamicNavbarProps> = ({ items, className = "", onChange }) => {
  const navigate = useNavigate();
  const { isAuthenticated, user, logout } = useAuth();
  
  useEffect(() => {
    // Initialize scroll handling
    const handleScroll = () => {
      const navbar = document.getElementById("main-navbar");
      const contentElement = document.getElementsByClassName("content-section")[0];
      
      if (navbar && contentElement) {
        // Cast to HTMLElement to access offsetTop
        const content = contentElement as HTMLElement;
        
        // 100px threshold after the content section starts
        const sticky = content.offsetTop + 100;
        
        if (window.scrollY > sticky) {
          navbar.classList.add("navbar-sticky");
          
          // Add hide-on-scroll-down functionality
          if (window.scrollY > lastScrollTop && window.scrollY > navbar.offsetHeight) {
            navbar.classList.add("navbar-hidden");
          } else {
            navbar.classList.remove("navbar-hidden");
          }
        } else {
          navbar.classList.remove("navbar-sticky");
          navbar.classList.remove("navbar-hidden");
        }
        
        // Save current scroll position
        lastScrollTop = window.scrollY;
      }
    };
    
    // Track last scroll position to determine direction
    let lastScrollTop = 0;
    
    // Run once on initial load
    handleScroll();
    
    // Add scroll event listener immediately
    window.addEventListener('scroll', handleScroll, { passive: true });
    
    // Clean up event listener on component unmount
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);
  
  return (
    <nav id="main-navbar" className="fixed top-0 left-0 right-0 z-50 w-full py-4 transition-all duration-300">
      <div className="container mx-auto px-6 flex items-center h-20">
        {/* Logo */}
        <div className="flex items-center">
          <Link to="/" className="text-xl font-bold text-arctic">TradeSage</Link>
        </div>

        {/* Center navigation tabs */}
        <div className="flex-1 flex justify-center">
          <ExpandableTabs
            tabs={(items ?? ([
              { title: 'Home', icon: Home },
              { type: 'separator' },
              { title: 'Features', icon: Zap },
              { type: 'separator' },
              { title: 'Pricing', icon: DollarSign },
              { type: 'separator' },
              { title: 'Contact', icon: Phone }
            ] as NavTabItem[])) }
            activeColor="text-white" className="bg-transparent"
            onChange={(index) => {
              // If parent provided onChange prop, call it
              if (onChange) {
                onChange(index);
                return;
              }
              if (index === null) return;
              const mapping = ['Home', 'Features', 'Pricing', 'Contact'];
              const title = mapping[index];
              switch (title) {
                case 'Home':
                  navigate('/');
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                  break;
                case 'Features':
                  document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' });
                  break;
                case 'Pricing':
                  document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                  break;
                case 'Contact':
                  document.getElementById('contact')?.scrollIntoView({ behavior: 'smooth' });
                  break;
                default:
                  break;
              }
            }}
          />
        </div>

        {/* Auth / user controls */}
        {isAuthenticated ? (
          <div className="flex items-center gap-4">
            <Link to="/dashboard">
              <Button className="bg-plasma-purple hover:bg-plasma-purple/90 text-white rounded-full px-6 py-2">
                Dashboard
              </Button>
            </Link>
            
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="relative h-10 w-10 rounded-full">
                  <UserCircle className="h-6 w-6 text-arctic" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56" align="end">
                <DropdownMenuLabel>My Account</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/profile">Profile</Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link to="/settings">Settings</Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={logout}>
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        ) : (
          <div className="flex items-center gap-4">
            <Link to="/auth/login">
              <Button variant="ghost" className="text-arctic hover:text-white">
                Login
              </Button>
            </Link>
            <Link to="/auth/signup">
              <Button className="bg-plasma-purple hover:bg-plasma-purple/90 text-white rounded-full px-6 py-2">
                Get Started
              </Button>
            </Link>
          </div>
        )}
      </div>
      
      <style>
        {`
          #main-navbar {
            background-color: transparent;
            transition: all 0.3s ease;
            height: 5rem;
          }
          
          .navbar-sticky {
            background-color: rgba(3, 3, 3, 0.8) !important;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            transform: translateY(0);
            transition: transform 0.3s ease;
          }
          
          .navbar-hidden {
            transform: translateY(-100%);
            transition: transform 0.3s ease;
          }
          
          @media (max-width: 768px) {
            #main-navbar {
              padding: 0.75rem 0;
            }
          }
        `}
      </style>
    </nav>
  );
};

export default DynamicNavbar;