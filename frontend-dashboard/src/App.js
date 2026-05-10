import React from 'react';
import Dashboard from './components/Dashboard';

function App() {
  return (
    <div className="App">
      <header>
        <h1>Cloud Network Security Monitor</h1>
      </header>
      <main>
        {/* The core security dashboard component */}
        <Dashboard />
      </main>
    </div>
  );
}

export default App;