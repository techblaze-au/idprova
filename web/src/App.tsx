import { useState } from 'react';
import { KeyProvider } from './store/keys';
import { Layout, type TabId } from './components/Layout';
import { KeygenPanel } from './components/KeygenPanel';
import { AidPanel } from './components/AidPanel';
import { DatPanel } from './components/DatPanel';
import { RevocationPanel } from './components/RevocationPanel';
import { ReceiptPanel } from './components/ReceiptPanel';
import { DashboardPanel } from './components/DashboardPanel';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('keygen');
  const [registryUrl, setRegistryUrl] = useState('');

  return (
    <KeyProvider>
      <Layout
        activeTab={activeTab}
        onTabChange={setActiveTab}
        registryUrl={registryUrl}
        onRegistryUrlChange={setRegistryUrl}
      >
        {activeTab === 'keygen' && <KeygenPanel />}
        {activeTab === 'aid' && <AidPanel registryUrl={registryUrl} />}
        {activeTab === 'dat' && <DatPanel registryUrl={registryUrl} />}
        {activeTab === 'revocation' && <RevocationPanel registryUrl={registryUrl} />}
        {activeTab === 'receipt' && <ReceiptPanel />}
        {activeTab === 'dashboard' && <DashboardPanel registryUrl={registryUrl} />}
      </Layout>
    </KeyProvider>
  );
}
