import { useState, useRef, useEffect } from 'react';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export function OverviewChat({ projectId }: { projectId: string }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        "Hi! I'm your AI assistant. Ask me about the agents, files, findings, or what to look for in this project.",
    },
  ]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || sending) return;
    setInput('');
    setSending(true);

    const userMsg: ChatMessage = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const res = await fetch(`/api/projects/${projectId}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text }),
      });
      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.response || data.error || 'No response' },
      ]);
    } catch (e: any) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `Error: ${e.message || e}` }]);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div
      style={{
        background: 'rgba(15, 15, 26, 0.95)',
        borderRadius: '16px',
        border: '1px solid rgba(255,255,255,0.05)',
        marginBottom: '24px',
        overflow: 'hidden',
        transition: 'all 0.3s ease',
      }}
    >
      {/* Header / Toggle */}
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '16px 20px',
          cursor: 'pointer',
          userSelect: 'none',
          borderBottom: open ? '1px solid rgba(255,255,255,0.05)' : 'none',
          transition: 'border 0.2s',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '20px' }}>🤖</span>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: '600', margin: 0 }}>AI Assistant</h3>
            <p style={{ fontSize: '11px', color: '#666', margin: '2px 0 0' }}>
              Ask about agents, files, findings, or what to look for
            </p>
          </div>
        </div>
        <span
          style={{
            fontSize: '14px',
            color: '#888',
            transition: 'transform 0.3s',
            transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          }}
        >
          ▼
        </span>
      </div>

      {/* Chat body — only when open */}
      {open && (
        <div style={{ padding: '0 20px 20px' }}>
          {/* Messages */}
          <div
            style={{
              maxHeight: '320px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
              marginBottom: '14px',
              paddingRight: '4px',
            }}
          >
            {messages.map((msg, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  gap: '10px',
                  alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                }}
              >
                {msg.role === 'assistant' && (
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background:
                        'linear-gradient(135deg, rgba(170,136,255,0.3), rgba(0,212,255,0.2))',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '14px',
                      flexShrink: 0,
                    }}
                  >
                    🤖
                  </div>
                )}
                <div
                  style={{
                    background:
                      msg.role === 'user'
                        ? 'linear-gradient(135deg, rgba(0,212,255,0.15), rgba(0,212,255,0.05))'
                        : 'rgba(26, 26, 46, 0.8)',
                    borderRadius: msg.role === 'user' ? '14px 14px 4px 14px' : '14px 14px 14px 4px',
                    padding: '10px 14px',
                    fontSize: '13px',
                    lineHeight: '1.5',
                    color: msg.role === 'user' ? '#00d4ff' : '#e0e0e0',
                    border: `1px solid ${msg.role === 'user' ? 'rgba(0,212,255,0.2)' : 'rgba(255,255,255,0.06)'}`,
                  }}
                >
                  {msg.content}
                </div>
              </div>
            ))}
            {sending && (
              <div style={{ display: 'flex', gap: '10px', alignSelf: 'flex-start' }}>
                <div
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '50%',
                    background:
                      'linear-gradient(135deg, rgba(170,136,255,0.3), rgba(0,212,255,0.2))',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '14px',
                    flexShrink: 0,
                  }}
                >
                  🤖
                </div>
                <div
                  style={{
                    background: 'rgba(26, 26, 46, 0.8)',
                    borderRadius: '14px 14px 14px 4px',
                    padding: '10px 14px',
                    fontSize: '13px',
                    color: '#888',
                    border: '1px solid rgba(255,255,255,0.06)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <span style={{ animation: 'pulse 1.2s infinite' }}>●</span>
                  <span style={{ animation: 'pulse 1.2s infinite 0.2s' }}>●</span>
                  <span style={{ animation: 'pulse 1.2s infinite 0.4s' }}>●</span>
                  <style>{`
                    @keyframes pulse { 0%,100% { opacity: 0.3; } 50% { opacity: 1; } }
                  `}</style>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask a question..."
              disabled={sending}
              style={{
                flex: 1,
                padding: '10px 14px',
                borderRadius: '10px',
                border: '1px solid rgba(255,255,255,0.08)',
                background: 'rgba(0,0,0,0.3)',
                color: '#fff',
                fontSize: '13px',
                outline: 'none',
                transition: 'border 0.2s',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = 'rgba(0,212,255,0.3)';
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)';
              }}
            />
            <button
              onClick={sendMessage}
              disabled={!input.trim() || sending}
              style={{
                padding: '10px 18px',
                borderRadius: '10px',
                border: 'none',
                background:
                  input.trim() && !sending
                    ? 'linear-gradient(135deg, #aa88ff, #00d4ff)'
                    : 'rgba(255,255,255,0.06)',
                color: input.trim() && !sending ? '#fff' : '#555',
                cursor: input.trim() && !sending ? 'pointer' : 'default',
                fontWeight: '600',
                fontSize: '13px',
                transition: 'all 0.2s',
              }}
            >
              Send
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
