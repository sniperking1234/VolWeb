import "@fontsource/roboto/300.css";
import "@fontsource/roboto/400.css";
import "@fontsource/roboto/500.css";
import "@fontsource/roboto/700.css";
import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import MiniDrawer from "./components/SideBar";
import Cases from "./pages/cases/Cases";
import Dashboard from "./pages/dashboard/Dashboard";
import Evidences from "./pages/evidences/Evidences";
import Login from "./pages/auth/Login";
import CaseDetail from "./pages/cases/CaseDetail";
import Symbols from "./pages/symbols/Symbols";
import EvidenceDetail from "./pages/evidences/EvidenceDetails";
import { SnackbarProvider } from "./components/SnackbarProvider";
const darkTheme = createTheme({
  palette: {
    mode: "dark",
  },
});

const PrivateRoute = ({ children }: { children: JSX.Element }) => {
  const isAuthenticated = !!localStorage.getItem("access_token");
  return isAuthenticated ? children : <Navigate to="/login" />;
};

const App: React.FC = () => {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <SnackbarProvider>
                  <MiniDrawer />
                </SnackbarProvider>
              </PrivateRoute>
            }
          >
            <Route path="" element={<Dashboard />} />
            <Route path="cases" element={<Cases />} />
            <Route path="evidences" element={<Evidences />} />
            <Route path="symbols" element={<Symbols />} />
            <Route path="evidences/:id" element={<EvidenceDetail />} />
            <Route path="cases/:id" element={<CaseDetail />} />
          </Route>
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
