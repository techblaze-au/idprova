import { useKeys } from '../../store/keys';

interface Props {
  value: string;
  onChange: (label: string) => void;
  label?: string;
}

export function KeySelector({ value, onChange, label }: Props) {
  const { keys } = useKeys();

  return (
    <div>
      {label && <label className="block text-sm text-text-muted mb-1">{label}</label>}
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full"
      >
        <option value="">Select a key...</option>
        {keys.map(k => (
          <option key={k.label} value={k.label}>
            {k.label} ({k.publicKeyMultibase.slice(0, 12)}...)
          </option>
        ))}
      </select>
    </div>
  );
}
