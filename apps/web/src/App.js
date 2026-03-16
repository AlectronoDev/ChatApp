import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SessionProvider, useSession } from './context/SessionContext';
import AuthPage from './pages/AuthPage';
import AppPage from './pages/AppPage';
function GuardedApp() {
    const { state } = useSession();
    if (!state.isLoaded) {
        return (_jsx("div", { className: "flex h-full items-center justify-center", children: _jsx("div", { className: "text-gray-400", children: "Loading\u2026" }) }));
    }
    return (_jsxs(Routes, { children: [_jsx(Route, { path: "/auth", element: state.session?.token ? _jsx(Navigate, { to: "/", replace: true }) : _jsx(AuthPage, {}) }), _jsx(Route, { path: "/*", element: state.session?.token ? _jsx(AppPage, {}) : _jsx(Navigate, { to: "/auth", replace: true }) })] }));
}
export default function App() {
    return (_jsx(SessionProvider, { children: _jsx(BrowserRouter, { children: _jsx(GuardedApp, {}) }) }));
}
