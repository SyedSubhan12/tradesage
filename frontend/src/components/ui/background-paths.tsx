"use client";

import { motion } from "framer-motion";

function FloatingPaths({ position, color = "currentColor", scale = 1 }: { position: number; color?: string; scale?: number }) {
    const paths = Array.from({ length: 36 }, (_, i) => ({
        id: i,
        d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${
            380 - i * 5 * position
        } -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${
            152 - i * 5 * position
        } ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${
            684 - i * 5 * position
        } ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
        opacity: 0.35 + i * 0.04,
        width: (0.8 + i * 0.05) * scale,
    }));

    return (
        <motion.div 
            className="absolute inset-0 pointer-events-none"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1 }}
        >
            <svg
                className="w-full h-full"
                viewBox="0 0 696 316"
                fill="none"
                style={{ color }}
            >
                <title>Background Paths</title>
                {paths.map((path) => (
                    <motion.path
                        key={path.id}
                        d={path.d}
                        stroke="currentColor"
                        strokeWidth={path.width}
                        strokeOpacity={path.opacity}
                        filter="url(#glow)"
                        initial={{ pathLength: 0, opacity: 0 }}
                        animate={{
                            pathLength: [0, 1],
                            opacity: [0, path.opacity, path.opacity, 0],
                            pathOffset: [0, 1]
                        }}
                        transition={{
                            duration: 15 + Math.random() * 10,
                            repeat: Infinity,
                            ease: "linear",
                            delay: Math.random() * 2
                        }}
                    />
                ))}
                <defs>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                        <feMerge>
                            <feMergeNode in="coloredBlur"/>
                            <feMergeNode in="SourceGraphic"/>
                        </feMerge>
                    </filter>
                </defs>
            </svg>
        </motion.div>
    );
}

export function BackgroundPaths({ 
    color = "rgba(255,255,255,0.3)",
    scale = 1,
    className = ""
}: { 
    color?: string;
    scale?: number;
    className?: string;
}) {
    return (
        <div className={`absolute inset-0 overflow-hidden ${className}`}>
            <FloatingPaths position={1} color={color} scale={scale} />
            <FloatingPaths position={-1} color={color} scale={scale} />
            <div className="absolute inset-0 bg-gradient-to-t from-black/30 via-transparent to-black/30 pointer-events-none" />
        </div>
    );
} 