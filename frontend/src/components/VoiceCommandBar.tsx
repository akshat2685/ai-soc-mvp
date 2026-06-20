import React, { useState } from 'react';
import { Mic, Send, Command } from 'lucide-react';

export default function VoiceCommandBar() {
  const [command, setCommand] = useState('');
  const [response, setResponse] = useState('');
  const [isListening, setIsListening] = useState(false);

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!command.trim()) return;
    
    setResponse('Processing...');
    
    // Simulate API call to backend/soar/nl_parser.py
    setTimeout(() => {
      setResponse(`Executed playbook for: "${command}" (Simulated)`);
      setCommand('');
    }, 1000);
  };

  const toggleListen = () => {
    if (isListening) {
      setIsListening(false);
      return;
    }
    
    // Check for native SpeechRecognition support
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setResponse("Speech Recognition API is not supported in this browser.");
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';

    recognition.onstart = () => {
      setIsListening(true);
    };

    recognition.onresult = (event: any) => {
      const transcript = event.results[0][0].transcript;
      setCommand(transcript);
      setIsListening(false);
    };

    recognition.onerror = (event: any) => {
      setResponse(`Speech recognition error: ${event.error}`);
      setIsListening(false);
    };

    recognition.onend = () => {
      setIsListening(false);
    };

    recognition.start();
  };

  return (
    <div className="bg-slate-900 border border-slate-700 p-4 rounded-xl shadow-lg mt-4">
      <div className="flex items-center gap-2 mb-2">
        <Command className="w-4 h-4 text-emerald-400" />
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Natural Language SOAR</h3>
      </div>
      
      <form onSubmit={handleSubmit} className="flex gap-2">
        <div className="relative flex-1">
          <input 
            type="text" 
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            placeholder="Type or speak a command (e.g., 'Isolate IP 10.0.0.1')"
            className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-3 pr-10 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
          />
          <button 
            type="button"
            onClick={toggleListen}
            className={`absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-md transition-colors ${
              isListening ? 'bg-red-500/20 text-red-400 animate-pulse' : 'hover:bg-slate-800 text-slate-400'
            }`}
          >
            <Mic className="w-4 h-4" />
          </button>
        </div>
        <button 
          type="submit"
          className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
        >
          <Send className="w-4 h-4" />
          Execute
        </button>
      </form>
      
      {response && (
        <div className="mt-3 text-xs text-emerald-400 bg-emerald-950/30 p-2 rounded border border-emerald-900/30 font-mono">
          &gt; {response}
        </div>
      )}
    </div>
  );
}
