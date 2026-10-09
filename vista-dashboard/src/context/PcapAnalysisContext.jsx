import { useCallback, useEffect, useRef, useState } from 'react';
import {
  analyzeCsvWithBackend,
  analyzePcapWithBackend,
  fetchEbpfEvents,
  fetchEbpfStatus,
} from '../utils/apiClient';
import { PcapAnalysisContext } from './PcapAnalysisStore';

const EMPTY_ANALYSIS = {
  analysisId: null,
  file: null,
  analysisResult: null,
  status: 'idle',
  error: null,
  analyzedAt: null,
  dataMode: 'live',
};

const EMPTY_LIVE_TESTBED = {
  status: null,
  probes: [],
  events: [],
  freshnessSeconds: null,
  lastPolledAt: null,
  error: null,
  connected: false,
};

function getFileMetadata(file) {
  return {
    name: file.name,
    size: file.size,
    type: file.type,
  };
}

export function PcapAnalysisProvider({ children }) {
  const [analysis, setAnalysis] = useState(EMPTY_ANALYSIS);
  const [liveTestbed, setLiveTestbed] = useState(EMPTY_LIVE_TESTBED);
  const requestId = useRef(0);
  const livePollInFlight = useRef(false);

  const refreshLiveTestbed = useCallback(async () => {
    if (livePollInFlight.current) return;
    livePollInFlight.current = true;
    try {
      const [statusResult, eventsResult] = await Promise.allSettled([
        fetchEbpfStatus(),
        fetchEbpfEvents(50),
      ]);

      const nextStatus = statusResult.status === 'fulfilled' ? statusResult.value : null;
      const statusError = statusResult.status === 'rejected'
        ? (statusResult.reason instanceof Error ? statusResult.reason.message : String(statusResult.reason))
        : null;

      const nextEvents = eventsResult.status === 'fulfilled' && Array.isArray(eventsResult.value?.events)
        ? eventsResult.value.events
        : [];
      const eventError = eventsResult.status === 'rejected'
        ? (eventsResult.reason instanceof Error ? eventsResult.reason.message : String(eventsResult.reason))
        : null;

      const connected = nextStatus?.status === 'RUNNING' && nextStatus?.mode === 'NATIVE_KERNEL_EBPF';
      const now = new Date();

      setLiveTestbed({
        status: nextStatus,
        probes: nextStatus?.probes || [],
        events: nextEvents,
        freshnessSeconds: 0,
        lastPolledAt: now.toISOString(),
        error: statusError || eventError,
        connected,
      });
    } catch (err) {
      setLiveTestbed((prev) => ({
        ...prev,
        error: err instanceof Error ? err.message : String(err),
        connected: false,
      }));
    } finally {
      livePollInFlight.current = false;
    }
  }, []);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => {
      void refreshLiveTestbed();
    }, 100);

    const intervalTimer = window.setInterval(() => {
      void refreshLiveTestbed();
    }, 3500);

    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(intervalTimer);
    };
  }, [refreshLiveTestbed]);

  const analyzeFile = useCallback(async (file) => {
    const currentRequestId = ++requestId.current;
    const fileMetadata = getFileMetadata(file);
    const extension = file.name.split('.').pop()?.toLowerCase();

    setAnalysis({
      analysisId: null,
      file: fileMetadata,
      analysisResult: null,
      status: 'analyzing',
      error: null,
      analyzedAt: null,
      dataMode: 'pcap',
    });

    try {
      const response = extension === 'csv'
        ? await analyzeCsvWithBackend(file)
        : ['pcap', 'pcapng', 'cap'].includes(extension)
          ? await analyzePcapWithBackend(file)
          : null;

      if (!response) {
        throw new Error('Unsupported format. Upload a PCAP, PCAPNG, CAP, or CSV file.');
      }
      if (!Array.isArray(response.flows)) {
        throw new Error('The backend response did not include flow records.');
      }

      if (requestId.current === currentRequestId) {
        const analysisId = response.analysisId
          || `ANL-${file.name.slice(0, 6).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;

        setAnalysis({
          analysisId,
          file: fileMetadata,
          analysisResult: {
            ...response,
            analysisId,
          },
          status: 'success',
          error: null,
          analyzedAt: response.analyzedAt || new Date().toISOString(),
          dataMode: 'pcap',
        });
      }
    } catch (error) {
      if (requestId.current === currentRequestId) {
        setAnalysis({
          analysisId: null,
          file: fileMetadata,
          analysisResult: null,
          status: 'error',
          error: error instanceof Error ? error.message : String(error),
          analyzedAt: null,
          dataMode: 'pcap',
        });
      }
    }
  }, []);

  const clearAnalysis = useCallback(() => {
    requestId.current += 1;
    setAnalysis(EMPTY_ANALYSIS);
  }, []);

  return (
    <PcapAnalysisContext.Provider
      value={{
        ...analysis,
        liveTestbed,
        refreshLiveTestbed,
        analyzeFile,
        clearAnalysis,
      }}
    >
      {children}
    </PcapAnalysisContext.Provider>
  );
}
