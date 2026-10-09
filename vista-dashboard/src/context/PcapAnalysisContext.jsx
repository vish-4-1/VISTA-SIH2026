import { useCallback, useRef, useState } from 'react';
import { analyzeCsvWithBackend, analyzePcapWithBackend } from '../utils/apiClient';
import { PcapAnalysisContext } from './PcapAnalysisStore';

const EMPTY_ANALYSIS = {
  file: null,
  analysisResult: null,
  status: 'idle',
  error: null,
  analyzedAt: null,
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
  const requestId = useRef(0);

  const analyzeFile = useCallback(async (file) => {
    const currentRequestId = ++requestId.current;
    const fileMetadata = getFileMetadata(file);
    const extension = file.name.split('.').pop()?.toLowerCase();

    setAnalysis({
      file: fileMetadata,
      analysisResult: null,
      status: 'analyzing',
      error: null,
      analyzedAt: null,
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
        setAnalysis({
          file: fileMetadata,
          analysisResult: response,
          status: 'success',
          error: null,
          analyzedAt: new Date().toISOString(),
        });
      }
    } catch (error) {
      if (requestId.current === currentRequestId) {
        setAnalysis({
          file: fileMetadata,
          analysisResult: null,
          status: 'error',
          error: error instanceof Error ? error.message : String(error),
          analyzedAt: null,
        });
      }
    }
  }, []);

  const clearAnalysis = useCallback(() => {
    requestId.current += 1;
    setAnalysis(EMPTY_ANALYSIS);
  }, []);

  return (
    <PcapAnalysisContext.Provider value={{ ...analysis, analyzeFile, clearAnalysis }}>
      {children}
    </PcapAnalysisContext.Provider>
  );
}
