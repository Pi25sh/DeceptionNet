export default function TechniqueTag({ technique, compact = false }) {
  if (!technique) return null;
  const isSemantic = technique.source === 'semantic';
  const raw = typeof technique === 'string' ? technique : technique.technique;
  const label = raw.split(' - ')[0];
  const name = raw.split(' - ').slice(1).join(' - ');
  const weight = technique.weight ?? 0;

  return (
    <span
      className={`technique-tag ${isSemantic ? 'tag-semantic' : 'tag-rule'}`}
      title={isSemantic ? `Semantic match · weight ${weight}` : `Rule match · weight ${weight}`}
    >
      <span className="technique-tag-text">{label}</span>
      {!compact && name && <span className="technique-tag-name">{name}</span>}
    </span>
  );
}
