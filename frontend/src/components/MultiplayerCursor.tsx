import React, { useEffect, useState, useRef } from 'react';

interface MultiplayerCursorProps {
  incidentId: string;
}

export default function MultiplayerCursor({ incidentId }: MultiplayerCursorProps) {
  const [peers, setPeers] = useState<Record<string, { x: number; y: number }>>({});
  const wsRef = useRef<WebSocket | null>(null);
  const myId = useRef(`analyst_${Math.random().toString(36).substr(2, 5)}`);

  useEffect(() => {
    // Connect to FastAPI WebSocket
    const ws = new WebSocket(`ws://localhost:8000/ws/incident/${incidentId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'CURSOR_MOVE') {
        setPeers(prev => ({
          ...prev,
          [data.userId]: { x: data.x, y: data.y }
        }));
      } else if (data.type === 'USER_LEFT') {
        // Handle disconnect cleanup if necessary
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'CURSOR_MOVE',
          userId: myId.current,
          x: e.clientX,
          y: e.clientY
        }));
      }
    };

    window.addEventListener('mousemove', handleMouseMove);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      ws.close();
    };
  }, [incidentId]);

  return (
    <>
      {Object.entries(peers).map(([id, pos]) => (
        <div 
          key={id}
          className="pointer-events-none fixed z-50 flex items-center gap-2 transition-transform duration-75"
          style={{ transform: `translate(${pos.x}px, ${pos.y}px)` }}
        >
          {/* Custom SVG Cursor */}
          <svg width="18" height="24" viewBox="0 0 18 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M2 2L15.6364 10.9545L9.5 12.5L12 18.5L9.5 19.5L6.5 13.5L2 17.5V2Z" fill="#a855f7" stroke="white" strokeWidth="1.5"/>
          </svg>
          <span className="bg-purple-500 text-white text-[10px] font-bold px-2 py-0.5 rounded shadow-lg">
            {id}
          </span>
        </div>
      ))}
    </>
  );
}
