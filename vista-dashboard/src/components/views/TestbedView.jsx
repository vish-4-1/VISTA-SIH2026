import { useCallback, useEffect, useRef, useState } from 'react';
import ThreeCanvas from '../ThreeCanvas';
import { fetchEbpfEvents, fetchEbpfStatus } from '../../utils/apiClient';

const POLL_INTERVAL_MS = 2500;
const EMPTY_VALUE = '—';

function formatTimestamp(value) {
  if (!value) return EMPTY_VALUE;
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? String(value) : timestamp.toLocaleString();
}

function eventIdentity(event) {
  return [
    event.timestamp ?? '',
    event.eventType ?? '',
    event.pid ?? '',
    event.process_name ?? '',
  ].join(':');
}

function fieldValue(value) {
  return value === null || value === undefined || value === '' ? EMPTY_VALUE : String(value);
}

function probeStatus(status, name) {
  const probe = status?.probes?.find((item) => item.name === name);
  return probe?.status || EMPTY_VALUE;
}

function ProbeLine({ status, name, label }) {
  const value = probeStatus(status, name);
  const attached = value === 'ATTACHED';
  return (
    <div className="testbed-probe-row">
      <span>{label}</span>
      <span className={`probe-state${attached ? ' is-attached' : ''}`}>
        <span className="status-indicator" />
        {value}
      </span>
    </div>
  );
}

export default function TestbedView({ refreshKey = 0 }) {
  const [collectorStatus, setCollectorStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [statusError, setStatusError] = useState('');
  const [eventError, setEventError] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState('pc1');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [activity, setActivity] = useState(null);
  const latestEventKey = useRef(null);
  const activitySequence = useRef(0);
  const refreshInFlight = useRef(false);

  const refreshTelemetry = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    const [statusResult, eventsResult] = await Promise.allSettled([
      fetchEbpfStatus(),
      fetchEbpfEvents(50),
    ]);

    if (statusResult.status === 'fulfilled') {
      setCollectorStatus(statusResult.value);
      setStatusError('');
    } else {
      setStatusError(statusResult.reason instanceof Error
        ? statusResult.reason.message
        : String(statusResult.reason));
    }

    if (eventsResult.status === 'fulfilled') {
      const nextEvents = Array.isArray(eventsResult.value.events)
        ? [...eventsResult.value.events].sort((left, right) => {
          const leftTime = Date.parse(left.timestamp);
          const rightTime = Date.parse(right.timestamp);
          if (Number.isNaN(leftTime) || Number.isNaN(rightTime)) return 0;
          return rightTime - leftTime;
        })
        : [];
      setEvents(nextEvents);
      setEventError('');

      const newest = nextEvents[0];
      if (newest) {
        const identity = eventIdentity(newest);
        if (latestEventKey.current !== null && identity !== latestEventKey.current) {
          activitySequence.current += 1;
          setActivity({ event: newest, sequence: activitySequence.current });
        }
        latestEventKey.current = identity;
      }
    } else {
      setEventError(eventsResult.reason instanceof Error
        ? eventsResult.reason.message
        : String(eventsResult.reason));
    }
    refreshInFlight.current = false;
  }, []);

  useEffect(() => {
    const initialRefresh = window.setTimeout(() => {
      void refreshTelemetry();
    }, 0);
    const interval = window.setInterval(() => {
      void refreshTelemetry();
    }, POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(interval);
    };
  }, [refreshTelemetry, refreshKey]);

  const collectorConnected = collectorStatus?.status === 'RUNNING'
    && collectorStatus?.mode === 'NATIVE_KERNEL_EBPF';
  const tunnelState = 'UNKNOWN';

  const inspectEvent = (event) => {
    setSelectedEvent(event);
    activitySequence.current += 1;
    setActivity({ event, sequence: activitySequence.current });
  };

  return (
    <div className="testbed-page">
      <div className="testbed-heading">
        <div>
          <h2>3D IPsec testbed</h2>
          <p>Source: live eBPF telemetry · tunnel state is not exposed by the current API.</p>
        </div>
        <div className={`testbed-collector-status${collectorConnected ? ' is-online' : ''}`}>
          <span className="status-indicator" />
          <span>Collector</span>
          <strong>{statusError ? 'Disconnected' : collectorConnected ? 'Connected' : collectorStatus ? 'Unavailable' : 'Loading'}</strong>
        </div>
      </div>

      <div className="testbed-main">
        <section className="testbed-scene" aria-label="Interactive 3D PC1 to PC2 IPsec testbed">
          <div className="scene-identities" aria-hidden="true">
            <span>PC1</span>
            <span>IPsec / ESP · {tunnelState}</span>
            <span>PC2</span>
          </div>
          <ThreeCanvas
            selectedNode={selectedNodeId}
            onSelectNode={setSelectedNodeId}
            activity={activity}
            tunnelState={tunnelState}
          />
          <div className="scene-state">
            <span className={`status-indicator${collectorConnected ? ' is-online' : ''}`} />
            eBPF monitor · {collectorConnected ? 'Connected' : statusError ? 'Disconnected' : 'Unavailable'}
          </div>
        </section>

        <aside className="testbed-inspector" aria-label="Selected endpoint and collector details">
          <section className="inspector-section">
            <h3>Selected endpoint</h3>
            <p className="inspector-endpoint">{selectedNodeId.toUpperCase()}</p>
            <dl className="inspector-fields">
              <div><dt>Address</dt><dd>{EMPTY_VALUE}</dd></div>
              <div><dt>Endpoint state</dt><dd>{EMPTY_VALUE}</dd></div>
              <div><dt>Tunnel state</dt><dd>{tunnelState}</dd></div>
              <div><dt>SA / crypto details</dt><dd>{EMPTY_VALUE}</dd></div>
            </dl>
          </section>

          <section className="inspector-section">
            <h3>eBPF probe status</h3>
            {statusError ? (
              <p className="inspector-message">Unable to load collector status: {statusError}</p>
            ) : !collectorStatus ? (
              <p className="inspector-message">Loading collector status…</p>
            ) : (
              <div className="testbed-probe-list">
                <ProbeLine status={collectorStatus} name="kprobe:xfrm_output" label="XFRM_OUT" />
                <ProbeLine status={collectorStatus} name="kprobe:xfrm_input" label="XFRM_IN" />
                <ProbeLine status={collectorStatus} name="kprobe:sock_sendmsg" label="SOCK_SEND" />
              </div>
            )}
          </section>

          <section className="inspector-section selected-event">
            <h3>Selected event</h3>
            {selectedEvent ? (
              <dl className="inspector-fields">
                <div><dt>Type</dt><dd>{fieldValue(selectedEvent.eventType)}</dd></div>
                <div><dt>Process</dt><dd>{fieldValue(selectedEvent.process_name)}</dd></div>
                <div><dt>PID</dt><dd>{fieldValue(selectedEvent.pid)}</dd></div>
                <div><dt>Timestamp</dt><dd>{formatTimestamp(selectedEvent.timestamp)}</dd></div>
              </dl>
            ) : (
              <p className="inspector-message">Select a recent event to inspect it and highlight its direction.</p>
            )}
          </section>
        </aside>
      </div>

      <section className="testbed-events" aria-labelledby="testbed-events-title">
        <div className="testbed-events-heading">
          <div>
            <h3 id="testbed-events-title">Live telemetry &amp; event timeline</h3>
            <p>Recent events from <code>/api/ebpf/events?limit=50</code>. Select a row to highlight observed activity.</p>
          </div>
          <span className="section-meta">{events.length} events</span>
        </div>
        {eventError ? (
          <p className="inspector-message">Unable to receive live eBPF telemetry: {eventError}</p>
        ) : events.length === 0 ? (
          <p className="inspector-message">
            {!eventError && !collectorStatus
              ? 'Loading collector events…'
              : 'No recent IPsec events. Generate traffic between PC1 and PC2 to observe XFRM telemetry.'}
          </p>
        ) : (
          <div className="testbed-event-scroll">
            <div className="testbed-event-header" aria-hidden="true">
              <span>Timestamp</span>
              <span>Event</span>
              <span>Process</span>
              <span>PID</span>
              <span>Bytes</span>
              <span>Packets</span>
            </div>
            <div className="testbed-event-list">
              {events.map((event, index) => {
                const identity = eventIdentity(event);
                const selected = selectedEvent && eventIdentity(selectedEvent) === identity;
                return (
                  <button
                    className={`testbed-event-row${selected ? ' is-selected' : ''}`}
                    key={`${identity}-${index}`}
                    type="button"
                    onClick={() => inspectEvent(event)}
                  >
                    <time dateTime={event.timestamp || undefined}>{formatTimestamp(event.timestamp)}</time>
                    <strong>{fieldValue(event.eventType)}</strong>
                    <span>{fieldValue(event.process_name)}</span>
                    <span>PID {fieldValue(event.pid)}</span>
                    <span>{fieldValue(event.bytes)}</span>
                    <span>{fieldValue(event.packets)}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
