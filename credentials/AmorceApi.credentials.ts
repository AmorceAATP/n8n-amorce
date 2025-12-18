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
