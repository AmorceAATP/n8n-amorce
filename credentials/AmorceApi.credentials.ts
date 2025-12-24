import {
    IAuthenticateGeneric,
    ICredentialTestRequest,
    ICredentialType,
    INodeProperties,
} from 'n8n-workflow';

export class AmorceApi implements ICredentialType {
    name = 'amorceApi';
    displayName = 'Amorce API';
    documentationUrl = 'https://amorce.io/docs/api';

    properties: INodeProperties[] = [
        {
            displayName: 'Directory URL',
            name: 'directoryUrl',
            type: 'string',
            default: 'https://trust.amorce.io/api/v1',
            placeholder: 'https://trust.amorce.io/api/v1',
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
            placeholder: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----',
            description: 'Your agent\'s Ed25519 private key for signing transactions (PEM format)',
        },
    ];

    authenticate: IAuthenticateGeneric = {
        type: 'generic',
        properties: {
            headers: {
                'Content-Type': 'application/json',
            },
        },
    };

    test: ICredentialTestRequest = {
        request: {
            baseURL: '={{$credentials.directoryUrl}}',
            url: '/v1/health',
            method: 'GET',
        },
    };
}
