import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SessionProvider, useSession } from './context/SessionContext';
import AuthPage from './pages/AuthPage';
import AppPage from './pages/AppPage';

function GuardedApp() {
  const { state } = useSession();

  if (!state.isLoaded) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-gray-400">Loading…</div>
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/auth"
        element={state.session?.token ? <Navigate to="/" replace /> : <AuthPage />}
      />
      <Route
        path="/*"
        element={state.session?.token ? <AppPage /> : <Navigate to="/auth" replace />}
      />
    </Routes>
  );
}

export default function App() {
  return (
    <SessionProvider>
      <BrowserRouter>
        <GuardedApp />
      </BrowserRouter>
    </SessionProvider>
  );
}
