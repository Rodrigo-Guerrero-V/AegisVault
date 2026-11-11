// src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { initTheme } from "./hooks/useTheme";
import "./styles/theme.css";

initTheme();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
