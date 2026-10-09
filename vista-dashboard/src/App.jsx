import { useEffect, useState } from 'react';
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
import { PcapAnalysisProvider } from './context/PcapAnalysisContext';

const VALID_TABS = new Set([
  'overview',
  'testbed',
  'traffic',
  'ai',
  'security',
  'threat',
  'reports',
  'dataset',
]);

const EMPTY_VIEWS = {
  ai: {
    title: 'AI analysis',
    message: 'No live classification result is available from current telemetry.',
  },
  security: {
    title: 'Security assessment',
    message: 'No assessment findings are available from observed testbed state.',
  },
  threat: {
    title: 'Threat intelligence',
    message: 'No threat findings are available from observed testbed telemetry.',
  },
  reports: {
    title: 'Reports',
    message: 'No data-backed assessment is available to generate a report.',
  },
  dataset: {
    title: 'Dataset',
    message: 'No live dataset information is exposed by the current API.',
  },
};

function EmptyView({ title, message }) {
  return (
    <div className="dashboard-content">
      <section className="dashboard-section" aria-labelledby="empty-view-title">
        <div className="section-heading">
          <div>
            <h2 id="empty-view-title">{title}</h2>
          </div>
        </div>
        <div className="dashboard-empty">{message}</div>
      </section>
    </div>
  );
}

function getTabFromUrl() {
  if (typeof window === 'undefined') {
    return 'overview';
  }

  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab');
  return VALID_TABS.has(tab) ? tab : 'overview';
}

export default function App() {
  const [activeTab, setActiveTab] = useState(getTabFromUrl);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const handlePopState = () => {
      setActiveTab(getTabFromUrl());
    };

    const url = new URL(window.location.href);
    if (!url.searchParams.has('tab')) {
      url.searchParams.set('tab', activeTab);
      window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
    }

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [activeTab]);

  const navigateToTab = (nextTab) => {
    if (!VALID_TABS.has(nextTab)) {
      return;
    }

    const currentTab = new URL(window.location.href).searchParams.get('tab');
    if (currentTab === nextTab) {
      setActiveTab(nextTab);
      return;
    }

    setActiveTab(nextTab);

    const url = new URL(window.location.href);
    url.searchParams.set('tab', nextTab);
    window.history.pushState({}, '', `${url.pathname}${url.search}${url.hash}`);
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewView refreshKey={refreshKey} />;
      case 'testbed':
        return <TestbedView refreshKey={refreshKey} />;
      case 'traffic':
        return <TrafficAnalysisView />;
      case 'ai':
        return <AiAnalysisView />;
      case 'security':
        return <SecurityAssessmentView />;
      case 'threat':
        return <ThreatIntelligenceView />;
      case 'reports':
        return <ReportsView />;
      case 'dataset':
        return <DatasetView />;
      default:
        return <OverviewView refreshKey={refreshKey} />;
    }
  };

  const unsupportedView = !VALID_TABS.has(activeTab) ? EMPTY_VIEWS[activeTab] : undefined;
  const content = unsupportedView
    ? <EmptyView {...unsupportedView} />
    : renderActiveView();

  return (
    <PcapAnalysisProvider>
      <div className="app-shell">
        <Sidebar activeTab={activeTab} onNavigate={navigateToTab} />
        <div className="app-main">
          <TopNav onRefresh={() => setRefreshKey((key) => key + 1)} activeTab={activeTab} />
          <main className="app-viewport">
            <ErrorBoundary key={activeTab}>{content}</ErrorBoundary>
          </main>
        </div>
      </div>
    </PcapAnalysisProvider>
  );
}
