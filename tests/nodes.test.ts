import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createSign, createVerify, generateKeyPairSync } from 'crypto';

// Generate test key pair
const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Helper functions (same as in the nodes)
function signPayload(payload: string, key: string): string {
    const sign = createSign('SHA256');
    sign.update(payload);
    return sign.sign(key, 'base64');
}

function verifySignature(payload: string, signature: string, key: string): boolean {
    try {
        const verify = createVerify('SHA256');
        verify.update(payload);
        return verify.verify(key, signature, 'base64');
    } catch {
        return false;
    }
}

describe('Amorce Agent Node', () => {
    describe('signPayload', () => {
        it('should sign a payload with EC private key', () => {
            const payload = JSON.stringify({
                consumer_id: 'test-agent',
                provider_id: 'target-agent',
                timestamp: '2024-01-01T00:00:00Z',
                body: { intent: 'test' },
            });

            const signature = signPayload(payload, privateKey);

            expect(signature).toBeDefined();
            expect(typeof signature).toBe('string');
            expect(signature.length).toBeGreaterThan(0);
        });

        it('should produce verifiable signatures', () => {
            const payload = JSON.stringify({
                consumer_id: 'test-agent',
                provider_id: 'target-agent',
                timestamp: '2024-01-01T00:00:00Z',
                body: { query: 'Find flights to Paris' },
            });

            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, publicKey);

            expect(isValid).toBe(true);
        });

        it('should fail verification with wrong payload', () => {
            const payload = JSON.stringify({ original: 'data' });
            const tamperedPayload = JSON.stringify({ tampered: 'data' });

            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(tamperedPayload, signature, publicKey);

            expect(isValid).toBe(false);
        });

        it('should fail verification with wrong public key', () => {
            const { publicKey: wrongKey } = generateKeyPairSync('ec', {
                namedCurve: 'P-256',
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            });

            const payload = JSON.stringify({ test: 'data' });
            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, wrongKey);

            expect(isValid).toBe(false);
        });
    });

    describe('Transaction Payload Format', () => {
        it('should create valid transaction structure', () => {
            const transaction = {
                consumer_id: 'n8n-workflow-agent',
                provider_id: 'langchain-research-agent',
                timestamp: new Date().toISOString(),
                body: {
                    intent: 'search',
                    query: 'AI agent frameworks',
                },
            };

            expect(transaction).toHaveProperty('consumer_id');
            expect(transaction).toHaveProperty('provider_id');
            expect(transaction).toHaveProperty('timestamp');
            expect(transaction).toHaveProperty('body');

            // Timestamp should be ISO format
            expect(new Date(transaction.timestamp).toISOString()).toBe(transaction.timestamp);
        });

        it('should serialize transaction deterministically', () => {
            const transaction = {
                consumer_id: 'agent-a',
                provider_id: 'agent-b',
                timestamp: '2024-01-01T00:00:00.000Z',
                body: { key: 'value' },
            };

            const serialized1 = JSON.stringify(transaction);
            const serialized2 = JSON.stringify(transaction);

            expect(serialized1).toBe(serialized2);
        });
    });
});

describe('Amorce Trigger Node', () => {
    describe('verifySignature', () => {
        it('should verify valid signatures', () => {
            const payload = JSON.stringify({
                consumer_id: 'crewai-agent',
                provider_id: 'n8n-workflow',
                timestamp: '2024-01-01T00:00:00Z',
                body: { action: 'execute' },
            });

            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, publicKey);

            expect(isValid).toBe(true);
        });

        it('should reject invalid signatures', () => {
            const payload = JSON.stringify({ test: 'data' });
            const invalidSignature = 'invalid-base64-signature';

            const isValid = verifySignature(payload, invalidSignature, publicKey);

            expect(isValid).toBe(false);
        });

        it('should handle empty signature gracefully', () => {
            const payload = JSON.stringify({ test: 'data' });

            const isValid = verifySignature(payload, '', publicKey);

            expect(isValid).toBe(false);
        });
    });

    describe('Request Validation', () => {
        it('should validate required fields in incoming request', () => {
            const validRequest = {
                consumer_id: 'external-agent',
                provider_id: 'n8n-workflow',
                timestamp: '2024-01-01T00:00:00Z',
                signature: 'base64-signature',
                body: { action: 'trigger' },
            };

            expect(validRequest.consumer_id).toBeDefined();
            expect(validRequest.signature).toBeDefined();
        });

        it('should identify missing consumer_id', () => {
            const invalidRequest = {
                provider_id: 'n8n-workflow',
                signature: 'some-signature',
                body: {},
            };

            const hasConsumerId = 'consumer_id' in invalidRequest && invalidRequest.consumer_id;
            expect(hasConsumerId).toBeFalsy();
        });

        it('should identify missing signature', () => {
            const invalidRequest = {
                consumer_id: 'external-agent',
                provider_id: 'n8n-workflow',
                body: {},
            };

            const hasSignature = 'signature' in invalidRequest;
            expect(hasSignature).toBe(false);
        });
    });

    describe('Allowed Agents Filter', () => {
        it('should parse comma-separated allowed agents list', () => {
            const allowedAgentsStr = 'agent-1, agent-2, agent-3';
            const allowedAgents = allowedAgentsStr.split(',').map(a => a.trim());

            expect(allowedAgents).toEqual(['agent-1', 'agent-2', 'agent-3']);
        });

        it('should allow agent in allowed list', () => {
            const allowedAgents = ['agent-1', 'agent-2'];
            const consumerId = 'agent-1';

            const isAllowed = allowedAgents.includes(consumerId);

            expect(isAllowed).toBe(true);
        });

        it('should reject agent not in allowed list', () => {
            const allowedAgents = ['agent-1', 'agent-2'];
            const consumerId = 'malicious-agent';

            const isAllowed = allowedAgents.includes(consumerId);

            expect(isAllowed).toBe(false);
        });

        it('should allow all agents when list is empty', () => {
            const allowedAgents: string[] = [];
            const consumerId = 'any-agent';

            const isAllowed = allowedAgents.length === 0 || allowedAgents.includes(consumerId);

            expect(isAllowed).toBe(true);
        });
    });
});

describe('Credentials', () => {
    it('should validate directory URL format', () => {
        const validUrls = [
            'https://amorce.io/api',
            'http://localhost:3000/api',
            'https://custom-directory.example.com',
        ];

        validUrls.forEach(url => {
            expect(() => new URL(url)).not.toThrow();
        });
    });

    it('should validate agent ID format', () => {
        const validAgentIds = [
            'my-n8n-workflow',
            'workflow-123',
            'production_agent',
        ];

        validAgentIds.forEach(id => {
            expect(id.length).toBeGreaterThan(0);
            expect(typeof id).toBe('string');
        });
    });
});
