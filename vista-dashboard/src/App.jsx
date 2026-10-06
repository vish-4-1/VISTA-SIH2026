import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import TopNav from './components/TopNav';
import OverviewView from './components/views/OverviewView';
import TestbedView from './components/views/TestbedView';
import TrafficAnalysisView from './components/views/TrafficAnalysisView';
import AiAnalysisView from './components/views/AiAnalysisView';
import SecurityAssessmentView from './components/views/SecurityAssessmentView';
import ThreatIntelligenceView from './components/views/ThreatIntelligenceView';
import ReportsView from './components/views/ReportsView';
import DatasetView from './components/views/DatasetView';
import ErrorBoundary from './components/ErrorBoundary';
import { ATTACK_SCENARIOS } from './data/networkData';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [scenario, setScenario] = useState(ATTACK_SCENARIOS.NORMAL);

  const renderActiveView = () => {
    switch (activeTab) {
      case 'testbed':
        return (
          <TestbedView
            scenario={scenario}
            onSelectScenario={(newSc) => setScenario(newSc)}
          />
        );
      case 'traffic':
        return <TrafficAnalysisView />;
      case 'ai':
        return <AiAnalysisView />;
      case 'security':
        return <SecurityAssessmentView />;
      case 'threats':
        return <ThreatIntelligenceView />;
      case 'reports':
        return <ReportsView />;
      case 'dataset':
        return <DatasetView />;
      case 'overview':
      default:
        return (
          <OverviewView
            scenario={scenario}
            onNavigateToTab={(tabId) => setActiveTab(tabId)}
            onSelectScenario={(newSc) => setScenario(newSc)}
          />
        );
    }
  };

  return (
    <div style={{
      width: '100vw',
      height: '100vh',
      display: 'flex',
      background: 'var(--bg-app)',
      color: 'var(--text-primary)',
      overflow: 'hidden'
    }}>
      {/* 1. Persistent Cybersecurity Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* 2. Main Application Workspace Area */}
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'hidden',
        position: 'relative'
      }}>
        {/* Top SOC Operation Nav Bar */}
        <TopNav
          currentScenario={scenario}
          onSelectScenario={(newSc) => setScenario(newSc)}
          onOpenTestbed={() => setActiveTab('testbed')}
        />

        {/* Scrollable Viewport Content */}
        <main style={{
          flex: 1,
          overflowY: activeTab === 'testbed' ? 'hidden' : 'auto',
          overflowX: 'hidden',
          position: 'relative'
        }} className="cyber-grid-bg">
          <ErrorBoundary key={activeTab}>
            {renderActiveView()}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
