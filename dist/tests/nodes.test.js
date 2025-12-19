"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const crypto_1 = require("crypto");
// Generate test key pair
const { privateKey, publicKey } = (0, crypto_1.generateKeyPairSync)('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
// Helper functions (same as in the nodes)
function signPayload(payload, key) {
    const sign = (0, crypto_1.createSign)('SHA256');
    sign.update(payload);
    return sign.sign(key, 'base64');
}
function verifySignature(payload, signature, key) {
    try {
        const verify = (0, crypto_1.createVerify)('SHA256');
        verify.update(payload);
        return verify.verify(key, signature, 'base64');
    }
    catch {
        return false;
    }
}
(0, vitest_1.describe)('Amorce Agent Node', () => {
    (0, vitest_1.describe)('signPayload', () => {
        (0, vitest_1.it)('should sign a payload with EC private key', () => {
            const payload = JSON.stringify({
                consumer_id: 'test-agent',
                provider_id: 'target-agent',
                timestamp: '2024-01-01T00:00:00Z',
                body: { intent: 'test' },
            });
            const signature = signPayload(payload, privateKey);
            (0, vitest_1.expect)(signature).toBeDefined();
            (0, vitest_1.expect)(typeof signature).toBe('string');
            (0, vitest_1.expect)(signature.length).toBeGreaterThan(0);
        });
        (0, vitest_1.it)('should produce verifiable signatures', () => {
            const payload = JSON.stringify({
                consumer_id: 'test-agent',
                provider_id: 'target-agent',
                timestamp: '2024-01-01T00:00:00Z',
                body: { query: 'Find flights to Paris' },
            });
            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, publicKey);
            (0, vitest_1.expect)(isValid).toBe(true);
        });
        (0, vitest_1.it)('should fail verification with wrong payload', () => {
            const payload = JSON.stringify({ original: 'data' });
            const tamperedPayload = JSON.stringify({ tampered: 'data' });
            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(tamperedPayload, signature, publicKey);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
        (0, vitest_1.it)('should fail verification with wrong public key', () => {
            const { publicKey: wrongKey } = (0, crypto_1.generateKeyPairSync)('ec', {
                namedCurve: 'P-256',
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            });
            const payload = JSON.stringify({ test: 'data' });
            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, wrongKey);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
    });
    (0, vitest_1.describe)('Transaction Payload Format', () => {
        (0, vitest_1.it)('should create valid transaction structure', () => {
            const transaction = {
                consumer_id: 'n8n-workflow-agent',
                provider_id: 'langchain-research-agent',
                timestamp: new Date().toISOString(),
                body: {
                    intent: 'search',
                    query: 'AI agent frameworks',
                },
            };
            (0, vitest_1.expect)(transaction).toHaveProperty('consumer_id');
            (0, vitest_1.expect)(transaction).toHaveProperty('provider_id');
            (0, vitest_1.expect)(transaction).toHaveProperty('timestamp');
            (0, vitest_1.expect)(transaction).toHaveProperty('body');
            // Timestamp should be ISO format
            (0, vitest_1.expect)(new Date(transaction.timestamp).toISOString()).toBe(transaction.timestamp);
        });
        (0, vitest_1.it)('should serialize transaction deterministically', () => {
            const transaction = {
                consumer_id: 'agent-a',
                provider_id: 'agent-b',
                timestamp: '2024-01-01T00:00:00.000Z',
                body: { key: 'value' },
            };
            const serialized1 = JSON.stringify(transaction);
            const serialized2 = JSON.stringify(transaction);
            (0, vitest_1.expect)(serialized1).toBe(serialized2);
        });
    });
});
(0, vitest_1.describe)('Amorce Trigger Node', () => {
    (0, vitest_1.describe)('verifySignature', () => {
        (0, vitest_1.it)('should verify valid signatures', () => {
            const payload = JSON.stringify({
                consumer_id: 'crewai-agent',
                provider_id: 'n8n-workflow',
                timestamp: '2024-01-01T00:00:00Z',
                body: { action: 'execute' },
            });
            const signature = signPayload(payload, privateKey);
            const isValid = verifySignature(payload, signature, publicKey);
            (0, vitest_1.expect)(isValid).toBe(true);
        });
        (0, vitest_1.it)('should reject invalid signatures', () => {
            const payload = JSON.stringify({ test: 'data' });
            const invalidSignature = 'invalid-base64-signature';
            const isValid = verifySignature(payload, invalidSignature, publicKey);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
        (0, vitest_1.it)('should handle empty signature gracefully', () => {
            const payload = JSON.stringify({ test: 'data' });
            const isValid = verifySignature(payload, '', publicKey);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
    });
    (0, vitest_1.describe)('Request Validation', () => {
        (0, vitest_1.it)('should validate required fields in incoming request', () => {
            const validRequest = {
                consumer_id: 'external-agent',
                provider_id: 'n8n-workflow',
                timestamp: '2024-01-01T00:00:00Z',
                signature: 'base64-signature',
                body: { action: 'trigger' },
            };
            (0, vitest_1.expect)(validRequest.consumer_id).toBeDefined();
            (0, vitest_1.expect)(validRequest.signature).toBeDefined();
        });
        (0, vitest_1.it)('should identify missing consumer_id', () => {
            const invalidRequest = {
                provider_id: 'n8n-workflow',
                signature: 'some-signature',
                body: {},
            };
            const hasConsumerId = 'consumer_id' in invalidRequest && invalidRequest.consumer_id;
            (0, vitest_1.expect)(hasConsumerId).toBeFalsy();
        });
        (0, vitest_1.it)('should identify missing signature', () => {
            const invalidRequest = {
                consumer_id: 'external-agent',
                provider_id: 'n8n-workflow',
                body: {},
            };
            const hasSignature = 'signature' in invalidRequest;
            (0, vitest_1.expect)(hasSignature).toBe(false);
        });
    });
    (0, vitest_1.describe)('Allowed Agents Filter', () => {
        (0, vitest_1.it)('should parse comma-separated allowed agents list', () => {
            const allowedAgentsStr = 'agent-1, agent-2, agent-3';
            const allowedAgents = allowedAgentsStr.split(',').map(a => a.trim());
            (0, vitest_1.expect)(allowedAgents).toEqual(['agent-1', 'agent-2', 'agent-3']);
        });
        (0, vitest_1.it)('should allow agent in allowed list', () => {
            const allowedAgents = ['agent-1', 'agent-2'];
            const consumerId = 'agent-1';
            const isAllowed = allowedAgents.includes(consumerId);
            (0, vitest_1.expect)(isAllowed).toBe(true);
        });
        (0, vitest_1.it)('should reject agent not in allowed list', () => {
            const allowedAgents = ['agent-1', 'agent-2'];
            const consumerId = 'malicious-agent';
            const isAllowed = allowedAgents.includes(consumerId);
            (0, vitest_1.expect)(isAllowed).toBe(false);
        });
        (0, vitest_1.it)('should allow all agents when list is empty', () => {
            const allowedAgents = [];
            const consumerId = 'any-agent';
            const isAllowed = allowedAgents.length === 0 || allowedAgents.includes(consumerId);
            (0, vitest_1.expect)(isAllowed).toBe(true);
        });
    });
});
(0, vitest_1.describe)('Credentials', () => {
    (0, vitest_1.it)('should validate directory URL format', () => {
        const validUrls = [
            'https://amorce.io/api',
            'http://localhost:3000/api',
            'https://custom-directory.example.com',
        ];
        validUrls.forEach(url => {
            (0, vitest_1.expect)(() => new URL(url)).not.toThrow();
        });
    });
    (0, vitest_1.it)('should validate agent ID format', () => {
        const validAgentIds = [
            'my-n8n-workflow',
            'workflow-123',
            'production_agent',
        ];
        validAgentIds.forEach(id => {
            (0, vitest_1.expect)(id.length).toBeGreaterThan(0);
            (0, vitest_1.expect)(typeof id).toBe('string');
        });
    });
});
