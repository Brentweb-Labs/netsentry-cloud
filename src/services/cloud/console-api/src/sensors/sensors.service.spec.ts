import { hashApiKey, newApiKey } from './sensors.service';

describe('sensor API keys', () => {
  it('creates prefixed random keys', () => {
    expect(newApiKey()).toMatch(/^nss_[0-9a-f]{48}$/);
    expect(newApiKey()).not.toBe(newApiKey());
  });

  it('stores keys as SHA-256 hashes, as the gateway expects', () => {
    expect(hashApiKey('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(hashApiKey('nss_x')).not.toContain('nss_x');
  });
});
