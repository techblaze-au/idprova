import { useState, useCallback } from 'react';

interface Props {
  text: string;
  label?: string;
}

export function CopyButton({ text, label }: Props) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="text-xs px-2 py-1 bg-surface2 border border-border rounded hover:bg-border text-text-muted"
      title="Copy to clipboard"
    >
      {copied ? 'Copied!' : label || 'Copy'}
    </button>
  );
}
