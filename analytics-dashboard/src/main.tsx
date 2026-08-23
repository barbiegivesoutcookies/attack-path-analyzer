import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// Application entry point. React 18 concurrent root API mounts the dashboard
// into the #root element declared in index.html.
const rootElement: HTMLElement | null = document.getElementById("root");
if (rootElement === null) {
  throw new Error("Root element '#root' not found in index.html");
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);