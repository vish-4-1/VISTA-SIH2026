import { useContext } from 'react';
import { PcapAnalysisContext } from './PcapAnalysisStore';

export function usePcapAnalysis() {
  const context = useContext(PcapAnalysisContext);
  if (!context) {
    throw new Error('usePcapAnalysis must be used within a PcapAnalysisProvider.');
  }
  return context;
}
