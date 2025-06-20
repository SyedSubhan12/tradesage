import React, { useEffect, useState, useRef } from 'react';

// Define the Particle type
interface Particle {
  id: number;
  x: number;
  y: number;
  symbol: string;
  size: number;
  animationDuration: number;
  animationDelay: number;
  glowColor: string;
}

const CurrencyParticlesBackground = () => {
  const currencySymbols = ['$', '€', '£', '¥', '₹', '₿'];
  const [particles, setParticles] = useState<Particle[]>([]);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    // Fixed positions in a more scattered pattern for left and right sides
    const leftPositions = [
      { x: 20, y: 15 },  // Top region left
      { x: 12, y: 55 },  // Middle region left (offset from vertical line)
      { x: 25, y: 85 }   // Bottom region left (offset from vertical line)
    ];
    
    const rightPositions = [
      { x: 80, y: 25 },  // Top region right (offset from left-side top)
      { x: 88, y: 50 },  // Middle region right (offset from vertical line)
      { x: 75, y: 75 }   // Bottom region right (offset from vertical line)
    ];

    // Create exactly 6 currency particles - 3 on left, 3 on right
    const initialParticles = currencySymbols.map((symbol, index) => {
      // Determine if symbol should be on left or right
      const isOnLeft = index < 3;
      
      // Get fixed position based on index
      const position = isOnLeft 
        ? leftPositions[index] 
        : rightPositions[index - 3];
      
      // Generate a color from purple to cyan spectrum for the glow
      const hue = isOnLeft 
        ? 260 + (index * 15)  // Purple-ish for left side (260-290)
        : 180 + (index * 15); // Cyan-ish for right side (195-225)
      
      return {
        id: index,
        x: position.x,
        y: position.y,
        symbol: symbol,
        size: 5 + (index % 3),  // Fixed sizes 5, 6, 7
        animationDuration: 8 + (index * 0.5), // Staggered durations
        animationDelay: index * 0.8, // Staggered delays
        glowColor: `hsl(${hue}, 100%, 70%)`,
      };
    });

    setParticles(initialParticles);
  }, [currencySymbols]);

  return (
    <div className="fixed inset-0 z-0 pointer-events-none bg-space-blue">
      {/* Purple gradient glow */}
      <div className="absolute top-0 right-0 w-[700px] h-[700px] rounded-full bg-plasma-purple/40 blur-[150px] opacity-90" />
      
      {/* Blue glow in another corner */}
      <div className="absolute bottom-0 left-0 w-[700px] h-[700px] rounded-full bg-electric-cyan/40 blur-[150px] opacity-90" />
      
      {/* Currency symbols with enhanced styling */}
      {particles.map((particle) => (
        <div 
          key={particle.id}
          className="absolute text-white pointer-events-none will-change-transform"
          style={{
            left: `${particle.x}vw`,
            top: `${particle.y}vh`,
            fontSize: `${particle.size}rem`,
            textShadow: `0 0 20px ${particle.glowColor}, 0 0 40px ${particle.glowColor}, 0 0 60px ${particle.glowColor}`,
            filter: `drop-shadow(0 0 8px ${particle.glowColor})`,
            animation: `float ${particle.animationDuration}s ease-in-out infinite`,
            animationDelay: `${particle.animationDelay}s`,
            opacity: 0.9,
            zIndex: 5,
          }}
        >
          {particle.symbol}
        </div>
      ))}

      <style>
        {`
          @keyframes float {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(35px) rotate(8deg); }
          }
        `}
      </style>
    </div>
  );
};

export default CurrencyParticlesBackground;