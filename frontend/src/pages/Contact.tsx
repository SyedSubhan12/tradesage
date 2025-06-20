import React from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import CurrencyParticlesBackground from '@/components/currency-background/CurrencyParticlesBackground';
import DynamicNavbar from '@/components/layout/DynamicNavbar';

const Contact = () => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Placeholder for contact form submission
    alert('Contact form submission is not yet implemented.');
  };

  return (
    <div className="relative min-h-screen bg-space-blue overflow-hidden">
      {/* Background */}
      <CurrencyParticlesBackground />
      
      {/* Navigation */}
      <DynamicNavbar />
      
      {/* Contact Form Section */}
      <section className="relative pt-24 min-h-[calc(100vh-80px)] flex flex-col items-center justify-center px-4 z-10">
        <div className="w-full max-w-md mx-auto">
          <div className="glass-panel p-8 rounded-xl">
            <h1 className="text-3xl font-bold text-arctic mb-6 text-center">Contact Us</h1>
            
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <label htmlFor="name" className="text-sm font-medium text-arctic">
                  Name
                </label>
                <Input 
                  id="name"
                  placeholder="Your name"
                  className="bg-white/5 border-white/10 text-arctic"
                />
              </div>
              
              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-arctic">
                  Email
                </label>
                <Input 
                  id="email"
                  type="email"
                  placeholder="Your email address"
                  className="bg-white/5 border-white/10 text-arctic"
                />
              </div>
              
              <div className="space-y-2">
                <label htmlFor="message" className="text-sm font-medium text-arctic">
                  Message
                </label>
                <Textarea 
                  id="message"
                  placeholder="How can we help you?"
                  className="bg-white/5 border-white/10 text-arctic"
                  rows={5}
                />
              </div>
              
              <Button 
                type="submit" 
                className="w-full bg-plasma-purple hover:bg-plasma-purple/90 text-white"
              >
                Send Message
              </Button>
            </form>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Contact; 