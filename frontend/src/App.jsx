import { Routes, Route } from 'react-router-dom';
import FlareLanding from './components/FlareLanding.jsx';
import LoginPage from './pages/LoginPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import './styles/tokens.css';
import './styles/app.css';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<FlareLanding />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/dashboard" element={
        <ProtectedRoute>
          <DashboardPage />
        </ProtectedRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute>
          <SettingsPage onBack={() => window.history.back()} />
        </ProtectedRoute>
      } />
      <Route path="*" element={
        <div className="flex min-h-screen items-center justify-center bg-background">
          <div className="text-center">
            <h1 className="text-4xl text-destructive">404</h1>
            <p className="text-muted-foreground">Page not found</p>
            <a href="/" className="text-accent">Go home</a>
          </div>
        </div>
      } />
    </Routes>
  );
}
