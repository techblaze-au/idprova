import { useState } from 'react';
import { CopyButton } from './CopyButton';

interface Props {
  data: unknown;
  title?: string;
  collapsed?: boolean;
}

export function JsonViewer({ data, title, collapsed = false }: Props) {
  const [isCollapsed, setIsCollapsed] = useState(collapsed);
  const json = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  return (
    <div className="bg-surface2 border border-border rounded-lg overflow-hidden">
      {title && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-border">
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="text-sm font-medium text-text-muted hover:text-text"
          >
            {isCollapsed ? '+ ' : '- '}{title}
          </button>
          <CopyButton text={json} />
        </div>
      )}
      {!isCollapsed && (
        <pre className="p-4 text-sm overflow-x-auto text-text">
          <code>{colorize(json)}</code>
        </pre>
      )}
    </div>
  );
}

function colorize(json: string): JSX.Element[] {
  // Simple syntax highlighting
  return json.split('\n').map((line, i) => {
    const highlighted = line
      .replace(/("[^"]+")(\s*:)/g, '<key></key>')
      .replace(/:\s*("[^"]*")/g, ': <str></str>')
      .replace(/:\s*(true|false)/g, ': <bool></bool>')
      .replace(/:\s*(\d+)/g, ': <num></num>');

    return (
      <span key={i}>
        {highlighted.split(/(<key>.*?<\/key>|<str>.*?<\/str>|<bool>.*?<\/bool>|<num>.*?<\/num>)/).map((part, j) => {
          if (part.startsWith('<key>')) return <span key={j} className="text-accent">{part.replace(/<\/?key>/g, '')}</span>;
          if (part.startsWith('<str>')) return <span key={j} className="text-success">{part.replace(/<\/?str>/g, '')}</span>;
          if (part.startsWith('<bool>')) return <span key={j} className="text-warning">{part.replace(/<\/?bool>/g, '')}</span>;
          if (part.startsWith('<num>')) return <span key={j} className="text-danger">{part.replace(/<\/?num>/g, '')}</span>;
          return <span key={j}>{part}</span>;
        })}
        {'\n'}
      </span>
    );
  });
}
