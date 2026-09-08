import AuthPanel from '../components/flare/AuthPanel.jsx';

export default function RegisterPage() {
  return (
    <div className="relative flex min-h-screen w-full items-center justify-center bg-black p-4 text-foreground selection:bg-primary/20 selection:text-primary">
      {/* Delicate Ambient Lighting Mesh */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <div className="absolute -top-32 left-1/2 -translate-x-1/2 h-[480px] w-[640px] rounded-full bg-primary/10 blur-[140px]" />
        <div className="absolute -bottom-40 left-1/2 -translate-x-1/2 h-[400px] w-[500px] rounded-full bg-indigo-500/5 blur-[160px]" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff04_1px,transparent_1px),linear-gradient(to_bottom,#ffffff04_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_40%,#000_60%,transparent_100%)] opacity-70" />
      </div>

      {/* Centered Minimal Card */}
      <div className="relative z-10 w-full flex justify-center py-8">
        <AuthPanel initialMode="register" />
      </div>
    </div>
  );
}
