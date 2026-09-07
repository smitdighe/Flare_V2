export default function Icon({ name, size = 18, className = '', title }) {
  return (
    <span
      aria-hidden={title ? undefined : 'true'}
      aria-label={title}
      className={`icon ${className}`}
      style={{ fontSize: size }}
    >
      {name}
    </span>
  );
}
