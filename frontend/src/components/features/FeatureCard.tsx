
import React from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader } from '@/components/ui/card';

interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

const FeatureCard = ({ icon, title, description }: FeatureCardProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      whileHover={{ 
        y: -5,
        boxShadow: "0 15px 30px rgba(0, 255, 157, 0.1)",
        transition: { duration: 0.2 }
      }}
    >
      <Card className="glass-panel h-full">
        <CardHeader className="pb-2 pt-6">
          <div className="mb-4">{icon}</div>
          <h3 className="text-2xl font-bold text-arctic">{title}</h3>
        </CardHeader>
        <CardContent>
          <p className="text-arctic/70">{description}</p>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default FeatureCard;
