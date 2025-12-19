"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AmorceApi = void 0;
class AmorceApi {
    constructor() {
        this.name = 'amorceApi';
        this.displayName = 'Amorce API';
        this.documentationUrl = 'https://amorce.io/docs/api';
        this.properties = [
            {
                displayName: 'Directory URL',
                name: 'directoryUrl',
                type: 'string',
                default: 'https://amorce.io/api',
                placeholder: 'https://amorce.io/api',
                description: 'The Amorce Trust Directory API URL',
            },
            {
                displayName: 'Agent ID',
                name: 'agentId',
                type: 'string',
                default: '',
                placeholder: 'my-n8n-workflow',
                description: 'Your registered agent ID in the Amorce Trust Directory',
            },
            {
                displayName: 'Private Key (PEM)',
                name: 'privateKey',
                type: 'string',
                typeOptions: {
                    password: true,
                    rows: 5,
                },
                default: '',
                placeholder: '-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----',
                description: 'Your agent\'s private key for signing transactions (EC P-256)',
            },
        ];
        this.authenticate = {
            type: 'generic',
            properties: {
                headers: {
                    'Content-Type': 'application/json',
                },
            },
        };
        this.test = {
            request: {
                baseURL: '={{$credentials.directoryUrl}}',
                url: '/v1/health',
                method: 'GET',
            },
        };
    }
}
exports.AmorceApi = AmorceApi;
