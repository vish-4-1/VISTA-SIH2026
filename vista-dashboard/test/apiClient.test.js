import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchSampleCaptures } from '../src/utils/apiClient.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('fetchSampleCaptures', () => {
  it('reports backend failure instead of converting it to an empty inventory', async () => {
    globalThis.fetch = async () => new Response('', { status: 503 });

    await assert.rejects(fetchSampleCaptures(), /inventory \(503\)/);
  });

  it('rejects malformed inventory records', async () => {
    globalThis.fetch = async () => Response.json([{ name: 'capture.pcap' }]);

    await assert.rejects(fetchSampleCaptures(), /response is invalid/);
  });

  it('returns valid backend capture inventory', async () => {
    const captures = [{ name: 'capture.pcap', sizeBytes: 42 }];
    globalThis.fetch = async () => Response.json(captures);

    assert.deepEqual(await fetchSampleCaptures(), captures);
  });
});
