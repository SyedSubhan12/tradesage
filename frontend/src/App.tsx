import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import MainLayout from "./components/layout/MainLayout";
import { AuthProvider, useAuth } from "./lib/authContext";

// Pages
import Index from "./pages/Index";
import Dashboard from "./pages/Dashboard";
import Strategies from "./pages/Strategies";
import NewsAnalysis from "./pages/NewsAnalysis";
import Backtest from "./pages/Backtest";
import NotFound from "./pages/NotFound";
import Contact from "./pages/Contact";

// Auth Pages
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ForgotPassword from "./pages/auth/ForgotPassword";
import OAuthCallback from "./pages/auth/OAuthCallback";

const queryClient = new QueryClient();

// Protected route component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  // If auth is still loading, show nothing
  if (isLoading) {
    return <div className="flex h-screen w-full items-center justify-center">Loading...</div>;
  }

  // If user is not authenticated, redirect to login
  if (!isAuthenticated) {
    return <Navigate to="/auth/login" />;
  }

  // If authenticated, render children
  return <>{children}</>;
};

const AppRoutes = () => {
  return (
    <div className="w-full min-h-screen bg-space-blue text-arctic">
      <Routes>
        <Route path="/" element={<Index />} />
        <Route path="/contact" element={<Contact />} />
        
        {/* Auth Routes */}
        <Route path="/auth/login" element={<Login />} />
        <Route path="/auth/signup" element={<Register />} />
        <Route path="/auth/forgot-password" element={<ForgotPassword />} />
        <Route path="/auth/callback" element={<OAuthCallback />} />
        
        {/* Protected App Routes */}
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <MainLayout>
              <Dashboard />
            </MainLayout>
          </ProtectedRoute>
        } />
        <Route path="/strategies" element={
          <ProtectedRoute>
            <MainLayout>
              <Strategies />
            </MainLayout>
          </ProtectedRoute>
        } />
        <Route path="/news" element={
          <ProtectedRoute>
            <MainLayout>
              <NewsAnalysis />
            </MainLayout>
          </ProtectedRoute>
        } />
        <Route path="/backtest" element={
          <ProtectedRoute>
            <MainLayout>
              <Backtest />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        {/* Other routes would go here */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </div>
  );
};

const App = () => (
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="w-full min-h-screen bg-space-blue">
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <AuthProvider>
              <AppRoutes />
            </AuthProvider>
          </BrowserRouter>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  </React.StrictMode>
);

export default App;
