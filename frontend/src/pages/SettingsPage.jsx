import { Navigate } from 'react-router-dom';

export default function SettingsPage() {
  return <Navigate to="/dashboard?section=settings" replace />;
}
