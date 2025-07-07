import React, { useEffect } from 'react';

import { motion } from "framer-motion";
import { Link } from 'react-router-dom';
import CurrencyParticlesBackground from '@/components/currency-background/CurrencyParticlesBackground';
import { Button } from '@/components/ui/button';
import { ArrowRight, Bot, ChevronRight, LineChart, PieChart, Zap, BarChart, Shield } from 'lucide-react';
import DynamicNavbar from '@/components/layout/DynamicNavbar';
import { useAuth } from '@/lib/authContext';
import { HeroGeometric } from '@/components/ui/shape-landing-hero';
import RadialOrbitalTimeline from '@/components/ui/radial-orbital-timeline';

const Index = () => {
  const { isAuthenticated } = useAuth();
  
  useEffect(() => {
    console.log('Index component mounted');
    console.log('isAuthenticated:', isAuthenticated);
    console.log('Document body:', document.body.offsetHeight);
  }, [isAuthenticated]);
  
  return (
    <div className="relative min-h-screen bg-[#030303] overflow-hidden">
      {/* Dynamic Navigation */}
      <DynamicNavbar />
      
      {/* Hero Section with Shapes */}
      <HeroGeometric 
        isAuthenticated={isAuthenticated}
        badge="AI-Powered Trading Platform"
        title1="Transform Your"
        title2="Trading Future"
      />
      
      {/* Features Section */}
      <section id="features" className="relative z-10 py-20 bg-[#030303]/90 backdrop-blur-md overflow-hidden">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-gradient-to-r from-indigo-500/10 to-rose-500/10 border border-white/20 backdrop-blur-sm shadow-[0_8px_32px_0_rgba(255,255,255,0.1)]"
            >
              <div className="h-2.5 w-2.5 rounded-full bg-gradient-to-r from-indigo-400 to-rose-400 animate-pulse shadow-[0_0_10px_rgba(255,255,255,0.3)]" />
              <span className="text-sm font-medium text-white/90 tracking-wide">
                Our Powerful Features
              </span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-white mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              AI-powered trading solutions
            </motion.h2>
            <motion.p 
              className="text-lg text-gray-300 max-w-2xl mx-auto mb-16"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              Experience the future of algorithmic trading with our cutting-edge features designed to optimize your investment strategy.
            </motion.p>

            <RadialOrbitalTimeline
              timelineData={[
                {
                  id: 1,
                  title: "AI Market Analysis",
                  date: "2024 Q1",
                  content: "Our AI analyzes market trends and news in real-time to provide actionable insights for your trading decisions.",
                  category: "AI",
                  icon: Bot,
                  relatedIds: [2, 5],
                  status: "completed",
                  energy: 90
                },
                {
                  id: 2,
                  title: "Algorithmic Trading",
                  date: "2024 Q1",
                  content: "Create and deploy custom trading strategies with our intuitive strategy builder and backtesting tools.",
                  category: "Trading",
                  icon: LineChart,
                  relatedIds: [1, 3],
                  status: "completed",
                  energy: 85
                },
                {
                  id: 3,
                  title: "Portfolio Optimization",
                  date: "2024 Q2",
                  content: "Automatically balance your portfolio based on risk tolerance and market conditions for optimal performance.",
                  category: "Portfolio",
                  icon: PieChart,
                  relatedIds: [2, 4],
                  status: "in-progress",
                  energy: 75
                },
                {
                  id: 4,
                  title: "Real-time Analytics",
                  date: "2024 Q2",
                  content: "Track your positions, market movements, and strategy performance with advanced real-time analytics.",
                  category: "Analytics",
                  icon: BarChart,
                  relatedIds: [3, 5],
                  status: "in-progress",
                  energy: 60
                },
                {
                  id: 5,
                  title: "Risk Management",
                  date: "2024 Q3",
                  content: "Advanced risk controls and position sizing algorithms to protect your capital and maximize returns.",
                  category: "Risk",
                  icon: Shield,
                  relatedIds: [1, 4],
                  status: "pending",
                  energy: 40
                }
              ]}
            />

            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.4 }}
              className="mt-16"
            >
            <Button 
              variant="outline" 
                className="border-white/20 bg-white/5 backdrop-blur-sm hover:bg-white/10 text-white"
            >
              Explore All Features <ChevronRight className="ml-2 h-4 w-4" />
            </Button>
            </motion.div>
          </div>
        </div>
      </section>
      
      {/* How It Works */}
      <section className="relative z-10 py-20 bg-[#0a0a0a]/90 backdrop-blur-md overflow-hidden">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center bg-white/5 backdrop-blur-sm border border-white/10 px-4 py-1 rounded-full mb-4"
            >
              <span className="text-sm text-white">Simple Process</span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-white mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              How TradeSage Works
            </motion.h2>
            <motion.p 
              className="text-lg text-gray-300 max-w-2xl mx-auto"
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
                className="bg-white/5 backdrop-blur-sm border border-white/10 p-8 rounded-xl relative"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: step * 0.2 }}
              >
                <div className="absolute -top-4 -left-4 h-12 w-12 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center text-xl font-bold text-white">
                  {step}
                </div>
                <h3 className="text-2xl font-bold text-white mb-4 mt-4">
                  {step === 1 ? "Create Account" : step === 2 ? "Set Preferences" : "Start Trading"}
                </h3>
                <p className="text-gray-300">
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
      <section id="pricing" className="relative z-10 py-20 bg-[#030303]/90 backdrop-blur-md overflow-hidden">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center bg-white/5 backdrop-blur-sm border border-white/10 px-4 py-1 rounded-full mb-4"
            >
              <span className="text-sm text-white">Pricing Plans</span>
            </motion.div>
            <motion.h2 
              className="text-4xl md:text-5xl font-bold text-white mb-4"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              Choose Your Plan
            </motion.h2>
            <motion.p 
              className="text-lg text-gray-300 max-w-2xl mx-auto"
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
                className={`bg-white/5 backdrop-blur-sm rounded-xl overflow-hidden ${plan.popular ? 'border-2 border-purple-500' : 'border border-white/10'}`}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.2 }}
              >
                {plan.popular && (
                  <div className="bg-gradient-to-r from-purple-500 to-pink-500 text-white text-center py-2 text-sm font-medium">
                    Most Popular
                  </div>
                )}
                <div className="p-8">
                  <h3 className="text-2xl font-bold text-white mb-2">{plan.name}</h3>
                  <div className="flex items-end mb-4">
                    <span className="text-4xl font-bold text-white">{plan.price}</span>
                    {plan.price !== "Custom" && <span className="text-gray-300 ml-1">/month</span>}
                  </div>
                  <p className="text-gray-300 mb-6">{plan.description}</p>
                  
                  <ul className="space-y-3 mb-8">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-center">
                        <Zap size={16} className="text-purple-400 mr-2" />
                        <span className="text-gray-200">{feature}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
                    <Button 
                      className={plan.popular ? "bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 w-full" : "bg-white/10 hover:bg-white/20 text-white w-full"}
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
      <section className="relative z-10 py-20 bg-[#0a0a0a]/90 backdrop-blur-md overflow-hidden">
        <div className="container mx-auto px-4">
          <motion.div 
            className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 backdrop-blur-sm rounded-2xl p-10 max-w-5xl mx-auto border border-white/10 relative overflow-hidden"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            {/* Purple glow */}
            <div className="absolute top-0 right-0 w-64 h-64 rounded-full bg-purple-500/30 blur-[100px]" />
            
            <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="md:max-w-xl">
                <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
                  Ready to transform your trading strategy?
                </h2>
                <p className="text-lg text-gray-300 mb-6">
                  Join thousands of traders who use TradeSage to gain a competitive edge in the markets.
                </p>
              </div>
              
              <div className="flex flex-col gap-4 w-full md:w-auto">
                <Link to={isAuthenticated ? "/dashboard" : "/auth/signup"}>
                  <Button className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-8 py-6 text-lg rounded-lg">
                    Start For Free
                  </Button>
                </Link>
                <Button variant="outline" className="border-white/10 hover:bg-white/5 text-white">
                  Book a Demo
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="relative z-10 py-12 bg-[#030303] backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <div>
              <h3 className="text-xl font-bold text-white mb-4">TradeSage</h3>
              <p className="text-gray-400 mb-4">
                AI-powered trading platform for modern investors.
              </p>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-gray-500 mb-4">Product</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-white">Features</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Pricing</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">API</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Integrations</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-gray-500 mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-white">Documentation</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Blog</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Tutorials</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Support</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-wider text-gray-500 mb-4">Company</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-white">About</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Careers</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Contact</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white">Legal</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-white/10 pt-8 mt-8 flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-500 text-sm">
              © {new Date().getFullYear()} TradeSage. All rights reserved.
            </p>
            
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a href="#" className="text-gray-500 hover:text-white">
                Twitter
              </a>
              <a href="#" className="text-gray-500 hover:text-white">
                LinkedIn
              </a>
              <a href="#" className="text-gray-500 hover:text-white">
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
