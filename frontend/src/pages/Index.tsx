import React, { useEffect } from 'react';

import { motion } from "framer-motion";
import { Link } from 'react-router-dom';
import CurrencyParticlesBackground from '@/components/currency-background/CurrencyParticlesBackground';
import { Button } from '@/components/ui/button';
import { ArrowRight, Bot, ChevronRight, LineChart, PieChart, Zap } from 'lucide-react';
import FeatureCard from '@/components/features/FeatureCard';
import DynamicNavbar from '@/components/layout/DynamicNavbar';
import { useAuth } from '@/lib/authContext';

const Index = () => {
  const { isAuthenticated } = useAuth();
  
  useEffect(() => {
    console.log('Index component mounted');
    console.log('isAuthenticated:', isAuthenticated);
    console.log('Document body:', document.body.offsetHeight);
  }, [isAuthenticated]);
  
  return (
    <div className="relative min-h-screen bg-space-blue overflow-hidden">
      {/* Background */}
      <CurrencyParticlesBackground />
      
      {/* Dynamic Navigation */}
      <DynamicNavbar />
      
      {/* Hero Section */}
      <section className="content-section relative pt-24 min-h-[calc(100vh-80px)] flex flex-col items-center justify-center px-4 z-10 text-center">
        <div className="mb-6 inline-flex items-center">
          <div className="bg-plasma-purple/20 backdrop-blur-sm px-4 py-1 rounded-full flex items-center">
            <span className="bg-plasma-purple text-white text-xs px-2 py-0.5 rounded-full mr-2">New</span>
            <span className="text-sm text-arctic">Automated Lead Generation</span>
          </div>
        </div>
        
        <motion.div 
          className="max-w-4xl text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <h1 className="text-5xl md:text-7xl font-bold text-arctic mb-6">
            <span className="block mb-2">Transform Your</span>
            <span className="block mb-2 neon-gradient">Liquid Futures</span>
            <span className="block">Trading Experience</span>
          </h1>
          <p className="text-xl text-arctic/70 mb-10 max-w-2xl mx-auto">
            TradeSage brings AI automation to your fingertips & streamline tasks.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
              <Button 
                className="bg-plasma-purple hover:bg-plasma-purple/90 text-white px-6 py-6 text-lg font-medium rounded-lg flex items-center"
                size="lg"
              >
                Get in touch <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Button 
              variant="outline"
              className="border-white/10 hover:bg-white/5 text-arctic"
              size="lg"
            >
              View services
            </Button>
          </div>
        </motion.div>

        {/* Bottom right button */}
        <div className="absolute bottom-8 right-8">
          <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
            <Button 
              className="bg-plasma-purple hover:bg-plasma-purple/90 text-white rounded-full px-6 flex items-center"
            >
              Use For Free <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </div>
      </section>
      
      {/* Features Section */}
      <section id="features" className="relative z-10 py-20 bg-space-blue/50 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center bg-white/5 backdrop-blur-sm border border-white/10 px-4 py-1 rounded-full mb-4"
            >
              <span className="text-sm text-arctic">Our Powerful Features</span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-arctic mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              AI-powered trading solutions
            </motion.h2>
            <motion.p 
              className="text-lg text-arctic/70 max-w-2xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              Experience the future of algorithmic trading with our cutting-edge features designed to optimize your investment strategy.
            </motion.p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard 
              icon={<Bot size={40} className="text-plasma-purple" />}
              title="AI Market Analysis"
              description="Our AI analyzes market trends and news in real-time to provide actionable insights for your trading decisions."
            />
            <FeatureCard 
              icon={<LineChart size={40} className="text-electric-cyan" />}
              title="Algorithmic Trading"
              description="Create and deploy custom trading strategies with our intuitive strategy builder and backtesting tools."
            />
            <FeatureCard 
              icon={<PieChart size={40} className="text-neon-green" />}
              title="Portfolio Optimization"
              description="Automatically balance your portfolio based on risk tolerance and market conditions for optimal performance."
            />
          </div>
          
          <div className="mt-16 text-center">
            <Button 
              variant="outline" 
              className="border-white/10 hover:bg-white/5 text-arctic"
            >
              Explore All Features <ChevronRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
      </section>
      
      {/* How It Works */}
      <section className="relative z-10 py-20 bg-space-blue/80 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center bg-white/5 backdrop-blur-sm border border-white/10 px-4 py-1 rounded-full mb-4"
            >
              <span className="text-sm text-arctic">Simple Process</span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-arctic mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              How TradeSage Works
            </motion.h2>
            <motion.p 
              className="text-lg text-arctic/70 max-w-2xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              Get started with our platform in three simple steps and transform your trading experience.
            </motion.p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[1, 2, 3].map((step) => (
              <motion.div 
                key={step}
                className="glass-panel p-8 rounded-xl relative"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: step * 0.2 }}
              >
                <div className="absolute -top-4 -left-4 h-12 w-12 rounded-full bg-plasma-purple flex items-center justify-center text-xl font-bold text-white">
                  {step}
                </div>
                <h3 className="text-2xl font-bold text-arctic mb-4 mt-4">
                  {step === 1 ? "Create Account" : step === 2 ? "Set Preferences" : "Start Trading"}
                </h3>
                <p className="text-arctic/70">
                  {step === 1 
                    ? "Sign up in minutes and connect your trading accounts securely." 
                    : step === 2 
                    ? "Configure your risk tolerance, trading style, and automation level."
                    : "Let our AI-powered platform optimize your trades and grow your portfolio."}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
      
      {/* Pricing Section */}
      <section id="pricing" className="relative z-10 py-20 bg-space-blue/50 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center bg-white/5 backdrop-blur-sm border border-white/10 px-4 py-1 rounded-full mb-4"
            >
              <span className="text-sm text-arctic">Pricing Plans</span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-arctic mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              Choose Your Plan
            </motion.h2>
            <motion.p 
              className="text-lg text-arctic/70 max-w-2xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              Flexible pricing options to match your trading needs and goals.
            </motion.p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            {[
              {
                name: "Starter",
                price: "$29",
                description: "Perfect for beginners looking to explore algorithmic trading.",
                features: [
                  "Basic AI market analysis",
                  "5 trading strategies",
                  "Standard backtesting",
                  "Email support"
                ]
              },
              {
                name: "Professional",
                price: "$99",
                description: "Advanced tools for experienced traders seeking an edge.",
                features: [
                  "Advanced AI market analysis",
                  "Unlimited trading strategies",
                  "Advanced backtesting",
                  "Priority support",
                  "Portfolio optimization"
                ],
                popular: true
              },
              {
                name: "Enterprise",
                price: "Custom",
                description: "Tailored solutions for institutional investors and funds.",
                features: [
                  "Custom AI models",
                  "Dedicated account manager",
                  "API access",
                  "White-label options",
                  "Custom integrations"
                ]
              }
            ].map((plan, index) => (
              <motion.div 
                key={plan.name}
                className={`glass-panel rounded-xl overflow-hidden ${plan.popular ? 'border-2 border-plasma-purple' : 'border border-white/10'}`}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.2 }}
              >
                {plan.popular && (
                  <div className="bg-plasma-purple text-white text-center py-2 text-sm font-medium">
                    Most Popular
                  </div>
                )}
                <div className="p-8">
                  <h3 className="text-2xl font-bold text-arctic mb-2">{plan.name}</h3>
                  <div className="flex items-end mb-4">
                    <span className="text-4xl font-bold text-arctic">{plan.price}</span>
                    {plan.price !== "Custom" && <span className="text-arctic/70 ml-1">/month</span>}
                  </div>
                  <p className="text-arctic/70 mb-6">{plan.description}</p>
                  
                  <ul className="space-y-3 mb-8">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-center">
                        <Zap size={16} className="text-neon-green mr-2" />
                        <span className="text-arctic/90">{feature}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
                    <Button 
                      className={plan.popular ? "bg-plasma-purple hover:bg-plasma-purple/90 w-full" : "bg-white/10 hover:bg-white/20 text-arctic w-full"}
                    >
                      Get Started
                    </Button>
                  </Link>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
      
      {/* CTA Section */}
      <section className="relative z-10 py-20 bg-space-blue/80 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <motion.div 
            className="glass-panel rounded-2xl p-10 max-w-5xl mx-auto bg-gradient-to-br from-space-blue to-black border border-white/10 relative overflow-hidden"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            {/* Purple glow */}
            <div className="absolute top-0 right-0 w-64 h-64 rounded-full bg-plasma-purple/30 blur-[100px]" />
            
            <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="md:max-w-xl">
                <h2 className="text-3xl md:text-4xl font-bold text-arctic mb-4">
                  Ready to transform your trading strategy?
                </h2>
                <p className="text-lg text-arctic/70 mb-6">
                  Join thousands of traders who use TradeSage to gain a competitive edge in the markets.
                </p>
              </div>
              
              <div className="flex flex-col gap-4 w-full md:w-auto">
                <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
                  <Button className="bg-plasma-purple hover:bg-plasma-purple/90 text-white px-8 py-6 text-lg rounded-lg">
                    Start For Free
                  </Button>
                </Link>
                <Button variant="outline" className="border-white/10 hover:bg-white/5 text-arctic">
                  Book a Demo
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="relative z-10 py-12 bg-space-blue/90 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <div>
              <h3 className="text-xl font-bold text-arctic mb-4">TradeSage</h3>
              <p className="text-arctic/70 mb-4">
                AI-powered trading platform for modern investors.
              </p>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-arctic/50 mb-4">Product</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Features</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Pricing</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">API</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Integrations</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-arctic/50 mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Documentation</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Blog</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Tutorials</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Support</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-arctic/50 mb-4">Company</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-arctic/70 hover:text-arctic">About</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Careers</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Contact</a></li>
                <li><a href="#" className="text-arctic/70 hover:text-arctic">Legal</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-white/10 pt-8 mt-8 flex flex-col md:flex-row justify-between items-center">
            <p className="text-arctic/50 text-sm">
              © {new Date().getFullYear()} TradeSage. All rights reserved.
            </p>
            
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a href="#" className="text-arctic/50 hover:text-arctic">
                Twitter
              </a>
              <a href="#" className="text-arctic/50 hover:text-arctic">
                LinkedIn
              </a>
              <a href="#" className="text-arctic/50 hover:text-arctic">
                GitHub
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
