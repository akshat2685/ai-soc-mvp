'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useStore } from '@/store/useStore';
import { api } from '@/lib/api';
import { 
  MessageSquare, 
  Send, 
  X, 
  Mic, 
  Volume2, 
  ChevronDown, 
  ChevronUp, 
  BookOpen, 
  Play, 
  CheckCircle,
  HelpCircle
} from 'lucide-react';

export default function CopilotDrawer() {
  const { user, currentTenant } = useStore();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState('');
  const [conversationId, setConversationId] = useState('');
  const [loading, setLoading] = useState(false);
  const [expandedReasoning, setExpandedReasoning] = useState<number | null>(null);
  const [isListening, setIsListening] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Initialize unique conversation ID
  useEffect(() => {
    setConversationId(`conv_${Date.now()}`);
  }, []);

  // Scroll to bottom on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = {
      role: 'user',
      content: input,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      // Call Copilot API
      const token = user?.token || '';
      const response = await fetch('http://localhost:8000/api/v1/copilot/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          conversation_id: conversationId,
          question: userMessage.content,
          history: messages.map(m => ({ role: m.role, content: m.content })),
          context_drilldown: { tenant_id: currentTenant }
        })
      });

      if (!response.ok) {
        throw new Error('Copilot response failed');
      }

      const data = await response.json();
      
      const copilotMessage = {
        role: 'copilot',
        content: data.answer,
        citations: data.citations || [],
        reasoning_steps: data.reasoning_steps || [],
        confidence_score: data.confidence_score || 0.9,
        timestamp: new Date().toISOString()
      };

      setMessages(prev => [...prev, copilotMessage]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          role: 'copilot',
          content: 'Sorry, I encountered an error retrieving security context.',
          timestamp: new Date().toISOString()
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const toggleVoice = () => {
    // Stub voice assistant logic
    if (isListening) {
      setIsListening(false);
    } else {
      setIsListening(true);
      setTimeout(() => {
        setIsListening(false);
        setInput('Show recent critical incidents and explain the attack path.');
      }, 2500);
    }
  };

  return (
    <>
      {/* Floating Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed bottom-6 right-6 z-40 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white p-4 rounded-full shadow-2xl transition-all hover:scale-105 active:scale-95 flex items-center justify-center group"
      >
        <MessageSquare className="w-6 h-6 group-hover:rotate-6 transition-all" />
        <span className="max-w-0 overflow-hidden group-hover:max-w-xs group-hover:ml-2 transition-all duration-300 ease-out text-xs font-bold uppercase tracking-wider">
          Ask Copilot
        </span>
      </button>

      {/* Slide-out Drawer Panel */}
      <div
        className={`fixed top-0 right-0 h-full w-[450px] bg-slate-900/95 border-l border-slate-800 backdrop-blur-xl z-50 shadow-2xl flex flex-col transition-transform duration-300 ease-out transform ${
          isOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {/* Header */}
        <div className="h-16 px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-5 h-5 text-blue-500" />
            <span className="font-bold text-sm bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-300">
              EDYSOR Security Copilot
            </span>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="text-slate-400 hover:text-white rounded-lg p-1 hover:bg-slate-800 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Chat Messages */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 p-4">
              <MessageSquare className="w-12 h-12 text-slate-700 mb-3" />
              <p className="text-sm font-semibold text-slate-400">Ask EDYSOR anything</p>
              <p className="text-xs text-slate-500 max-w-xs mt-1">
                "Why is host suspicious?", "Show ransomware incidents.", or "Explain attack path."
              </p>
            </div>
          )}

          {messages.map((msg, index) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={index}
                className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs leading-relaxed ${
                    isUser
                      ? 'bg-blue-600 text-white rounded-tr-none'
                      : 'bg-slate-800/80 border border-slate-700/60 text-slate-200 rounded-tl-none'
                  }`}
                >
                  <p>{msg.content}</p>
                  
                  {/* Citations & Multi-Step Reasoning Accordion */}
                  {!isUser && (msg.citations?.length > 0 || msg.reasoning_steps?.length > 0) && (
                    <div className="mt-3 pt-2.5 border-t border-slate-700/60 space-y-2 text-[10px]">
                      
                      {/* Confidence score */}
                      {msg.confidence_score !== undefined && (
                        <div className="flex items-center gap-1.5 text-blue-400 font-semibold">
                          <CheckCircle className="w-3.5 h-3.5 text-blue-400" />
                          <span>Threat Confidence: {Math.round(msg.confidence_score * 100)}%</span>
                        </div>
                      )}

                      {/* Expandable Reasoning Trace */}
                      {msg.reasoning_steps?.length > 0 && (
                        <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/30">
                          <button
                            onClick={() => setExpandedReasoning(expandedReasoning === index ? null : index)}
                            className="w-full flex items-center justify-between font-bold text-slate-400 hover:text-slate-200"
                          >
                            <span>Reasoning Traces</span>
                            {expandedReasoning === index ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>
                          {expandedReasoning === index && (
                            <ul className="mt-1.5 space-y-1 text-slate-400 list-disc list-inside">
                              {msg.reasoning_steps.map((step: string, sIdx: number) => (
                                <li key={sIdx} className="truncate">{step}</li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}

                      {/* Source Citation Badges */}
                      {msg.citations?.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          <span className="text-slate-500 font-semibold flex items-center gap-1">
                            <BookOpen className="w-3 h-3" /> Citations:
                          </span>
                          {msg.citations.map((cite: any, cIdx: number) => (
                            <span 
                              key={cIdx} 
                              className="bg-slate-900 border border-slate-700 px-2 py-0.5 rounded text-slate-300 font-mono"
                              title={cite.description}
                            >
                              {cite.key}
                            </span>
                          ))}
                        </div>
                      )}

                    </div>
                  )}
                </div>
                <span className="text-[9px] text-slate-600 mt-1 px-1">
                  {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            );
          })}

          {loading && (
            <div className="flex items-center gap-2 text-slate-500 text-xs px-2 animate-pulse">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce delay-75"></div>
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce delay-150"></div>
              <span>EDYSOR is thinking...</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <form onSubmit={handleSend} className="p-4 border-t border-slate-800 flex gap-2">
          <button
            type="button"
            onClick={toggleVoice}
            className={`p-3 rounded-xl border flex items-center justify-center transition-all ${
              isListening 
                ? 'bg-red-950/40 border-red-800 text-red-400 animate-pulse scale-105' 
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
            }`}
            title="Voice control (stub)"
          >
            <Mic className="w-4 h-4" />
          </button>
          
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Ask Copilot a question..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-xs focus:outline-none focus:border-blue-500 transition-all text-white placeholder-slate-600"
            disabled={loading}
          />
          
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white p-3 rounded-xl transition-all flex items-center justify-center shadow-lg shadow-blue-600/10 active:scale-95"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </>
  );
}
