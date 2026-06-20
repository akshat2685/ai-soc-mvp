'use client';

import React from 'react';
import { useStore } from '@/store/useStore';
import DashboardShell from '@/components/DashboardShell';
import DashboardView from '@/components/DashboardView';
import IncidentsView from '@/components/IncidentsView';
import AttackGraphView from '@/components/AttackGraphView';
import MemoryExplorerView from '@/components/MemoryExplorerView';
import ExecutiveDashboardView from '@/components/ExecutiveDashboardView';
import ReportingView from '@/components/ReportingView';
import SettingsView from '@/components/SettingsView';
import FederationDashboard from '@/components/FederationDashboard';
import ChaosDashboard from '@/components/ChaosDashboard';

export default function Home() {
  const { activePage } = useStore();

  const renderActiveView = () => {
    switch (activePage) {
      case 'dashboard':
        return <DashboardView />;
      case 'incidents':
        return <IncidentsView />;
      case 'graph':
        return <AttackGraphView />;
      case 'memory':
        return <MemoryExplorerView />;
      case 'executive':
        return <ExecutiveDashboardView />;
      case 'federation':
        return <FederationDashboard />;
      case 'chaos':
        return <ChaosDashboard />;
      case 'reporting':
        return <ReportingView />;
      case 'threat-intel':
        return <ReportingView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <DashboardShell>
      {renderActiveView()}
    </DashboardShell>
  );
}
