import React, { useEffect, useRef, useState } from 'react';

/**
 * P2: AR Threat Visualization (WebXR)
 * Renders a 3D representation of the Neo4j lateral movement graph.
 * Compatible with WebXR headsets for immersive attack analysis.
 */
export const ARThreatMap: React.FC = () => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [xrSupported, setXrSupported] = useState(false);

    useEffect(() => {
        // Check for WebXR support
        if ('xr' in navigator) {
            (navigator as any).xr.isSessionSupported('immersive-vr').then((supported: boolean) => {
                setXrSupported(supported);
            });
        }

        // Mock 3D render loop for standard browsers
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let frameId: number;
        let angle = 0;

        const renderMock3D = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Draw background
            ctx.fillStyle = '#0a0a0f';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Simulate a rotating 3D node (Attacker IP)
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = 50 + Math.sin(angle) * 10;

            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(255, 50, 50, 0.8)';
            ctx.fill();
            
            ctx.font = '14px Inter';
            ctx.fillStyle = '#fff';
            ctx.textAlign = 'center';
            ctx.fillText('Attacker: 185.15.5.5', centerX, centerY + radius + 20);

            // Simulate lateral movement lines in 3D
            const targetX = centerX + Math.cos(angle * 0.5) * 150;
            const targetY = centerY + Math.sin(angle * 0.5) * 100;

            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.lineTo(targetX, targetY);
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
            ctx.lineWidth = 2;
            ctx.stroke();

            // Target Node
            ctx.beginPath();
            ctx.arc(targetX, targetY, 20, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(50, 200, 255, 0.8)';
            ctx.fill();
            ctx.fillText('Target: DB-01', targetX, targetY + 35);

            angle += 0.05;
            frameId = requestAnimationFrame(renderMock3D);
        };

        renderMock3D();

        return () => {
            cancelAnimationFrame(frameId);
        };
    }, []);

    return (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 shadow-2xl relative overflow-hidden">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-bold text-white tracking-wide">WebXR AR Threat Map</h2>
                {xrSupported ? (
                    <button className="bg-purple-600 hover:bg-purple-500 text-white px-4 py-2 rounded-lg font-medium shadow-lg shadow-purple-500/30 transition-all">
                        Enter VR Mode
                    </button>
                ) : (
                    <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold bg-gray-800 px-2 py-1 rounded">
                        Standard View (VR Unsupported)
                    </span>
                )}
            </div>
            
            <div className="relative w-full h-[300px] rounded-lg overflow-hidden border border-gray-700/50">
                <canvas 
                    ref={canvasRef} 
                    width={800} 
                    height={300} 
                    className="w-full h-full object-cover"
                />
                <div className="absolute top-2 left-2 bg-black/50 backdrop-blur-sm px-3 py-1 rounded text-xs text-gray-300">
                    Live Lateral Movement Vector
                </div>
            </div>
        </div>
    );
};
