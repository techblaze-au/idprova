interface Props {
  status: 'pass' | 'fail' | 'warn';
  label: string;
}

const colors = {
  pass: 'bg-success/20 text-success border-success/30',
  fail: 'bg-danger/20 text-danger border-danger/30',
  warn: 'bg-warning/20 text-warning border-warning/30',
};

export function StatusBadge({ status, label }: Props) {
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${colors[status]}`}>
      {status === 'pass' ? 'PASS' : status === 'fail' ? 'FAIL' : 'WARN'}: {label}
    </span>
  );
}
