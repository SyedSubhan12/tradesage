
import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useIsMobile } from '@/hooks/use-mobile';

interface CurrencySymbolProps {
  symbol: string;
  initialX: string;
  initialY: string;
  size: number;
  delay: number;
  duration: number;
  opacity: number;
  zIndex: number;
  rotation: number;
}

const CurrencySymbol = ({ 
  symbol, 
  initialX, 
  initialY, 
  size, 
  delay, 
  duration, 
  opacity,
  zIndex,
  rotation
}: CurrencySymbolProps) => {
  return (
    <motion.div
      className="absolute text-white pointer-events-none select-none"
      style={{ 
        fontSize: `${size}px`, 
        x: initialX, 
        y: initialY,
        fontWeight: Math.random() > 0.5 ? 'normal' : 'bold',
        zIndex: zIndex
      }}
      initial={{ opacity: 0 }}
      animate={{ 
        y: [initialY, `calc(${initialY} - ${50 + Math.random() * 100}px)`, initialY],
        opacity: [opacity * 0.7, opacity, opacity * 0.7],
        rotate: [0, rotation, 0]
      }}
      transition={{
        duration: duration,
        repeat: Infinity,
        repeatType: "reverse",
        ease: "easeInOut",
        delay: delay
      }}
    >
      {symbol}
    </motion.div>
  );
};

const CurrencyBackground = () => {
  const isMobile = useIsMobile();
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const [symbols, setSymbols] = useState<Array<{
    symbol: string;
    initialX: string;
    initialY: string;
    size: number;
    delay: number;
    duration: number;
    opacity: number;
    zIndex: number;
    rotation: number;
    id: string;
  }>>([]);
  
  // Check if user prefers reduced motion
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);
    
    const handleChange = () => setPrefersReducedMotion(mediaQuery.matches);
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);
  
  // Generate symbols based on device and preferences
  useEffect(() => {
    const symbolsList = ["$", "€", "£", "¥", "₿", "₹", "₽", "₩", "⟠", "₴", "₺", "฿", "₡", "₢", "₫", "₮", "₱"];
    const count = isMobile ? 10 : prefersReducedMotion ? 8 : 20;
    
    const generatedSymbols = Array.from({ length: count }, (_, i) => {
      const randomX = Math.random() * 100;
      const randomY = Math.random() * 100;
      const randomSize = isMobile ? 
        (12 + Math.random() * 24) : 
        (16 + Math.random() * 56);
      const randomDelay = Math.random() * 5;
      const randomDuration = 10 + Math.random() * 20;
      const randomOpacity = 0.1 + Math.random() * 0.3;
      const randomZIndex = Math.floor(Math.random() * 3);
      const randomRotation = Math.random() > 0.5 ? (Math.random() * 10) : 0;
      const randomSymbol = symbolsList[Math.floor(Math.random() * symbolsList.length)];
      
      return {
        symbol: randomSymbol,
        initialX: `${randomX}vw`,
        initialY: `${randomY}vh`,
        size: randomSize,
        delay: randomDelay,
        duration: randomDuration,
        opacity: prefersReducedMotion ? randomOpacity * 0.5 : randomOpacity,
        zIndex: randomZIndex,
        rotation: randomRotation,
        id: `symbol-${i}-${randomSymbol}-${Math.random().toString(36).substring(2, 9)}`
      };
    });
    
    setSymbols(generatedSymbols);
  }, [isMobile, prefersReducedMotion]);
  
  // Don't render symbols if user prefers reduced motion strongly
  if (prefersReducedMotion && isMobile) {
    return null;
  }
  
  return (
    <div className="fixed inset-0 overflow-hidden z-0 pointer-events-none">
      {symbols.map((data) => (
        <CurrencySymbol
          key={data.id}
          symbol={data.symbol}
          initialX={data.initialX}
          initialY={data.initialY}
          size={data.size}
          delay={data.delay}
          duration={data.duration}
          opacity={data.opacity}
          zIndex={data.zIndex}
          rotation={data.rotation}
        />
      ))}
      <div className="absolute inset-0 bg-space-blue/30 backdrop-blur-[100px] pointer-events-none" />
    </div>
  );
};

export default CurrencyBackground;
