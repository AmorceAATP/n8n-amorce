import {
    IHookFunctions,
    IWebhookFunctions,
    INodeType,
    INodeTypeDescription,
    IWebhookResponseData,
    NodeOperationError,
} from 'n8n-workflow';
import { createVerify } from 'crypto';

export class AmorceTrigger implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'Amorce Trigger',
        name: 'amorceTrigger',
        icon: 'file:amorce.svg',
        group: ['trigger'],
        version: 1,
        subtitle: 'Receive verified agent requests',
        description: 'Trigger workflow when an AI agent sends a verified request via Amorce',
        defaults: {
            name: 'Amorce Trigger',
        },
        inputs: [],
        outputs: ['main'],
        credentials: [
            {
                name: 'amorceApi',
                required: true,
            },
        ],
        webhooks: [
            {
                name: 'default',
                httpMethod: 'POST',
                responseMode: 'onReceived',
                path: 'amorce',
            },
        ],
        properties: [
            {
                displayName: 'Verify Signatures',
                name: 'verifySignatures',
                type: 'boolean',
                default: true,
                description: 'Whether to verify incoming request signatures against the Amorce registry',
            },
            {
                displayName: 'Allowed Agents',
                name: 'allowedAgents',
                type: 'string',
                default: '',
                placeholder: 'agent-1, agent-2',
                description: 'Comma-separated list of agent IDs allowed to trigger this workflow (empty = allow all)',
            },
        ],
    };

    webhookMethods = {
        default: {
            async checkExists(this: IHookFunctions): Promise<boolean> {
                return true;
            },
            async create(this: IHookFunctions): Promise<boolean> {
                return true;
            },
            async delete(this: IHookFunctions): Promise<boolean> {
                return true;
            },
        },
    };

    async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
        const req = this.getRequestObject();
        const body = this.getBodyData();
        const credentials = await this.getCredentials('amorceApi');
        const directoryUrl = credentials.directoryUrl as string;

        const verifySignatures = this.getNodeParameter('verifySignatures') as boolean;
        const allowedAgentsStr = this.getNodeParameter('allowedAgents') as string;
        const allowedAgents = allowedAgentsStr
            ? allowedAgentsStr.split(',').map((a) => a.trim())
            : [];

        try {
            // Extract transaction data
            const { consumer_id, provider_id, timestamp, signature, body: requestBody } = body as any;

            if (!consumer_id || !signature) {
                return {
                    webhookResponse: {
                        status: 400,
                        body: { error: 'Missing consumer_id or signature' },
                    },
                };
            }

            // Check allowed agents
            if (allowedAgents.length > 0 && !allowedAgents.includes(consumer_id)) {
                return {
                    webhookResponse: {
                        status: 403,
                        body: { error: 'Agent not in allowed list' },
                    },
                };
            }

            // Verify signature if enabled
            if (verifySignatures) {
                // Fetch consumer's public key from directory
                const agentInfo = await this.helpers.request({
                    method: 'GET',
                    url: `${directoryUrl}/v1/agents/${encodeURIComponent(consumer_id)}`,
                    json: true,
                });

                if (!agentInfo.public_key) {
                    return {
                        webhookResponse: {
                            status: 401,
                            body: { error: 'Consumer agent not found in registry' },
                        },
                    };
                }

                // Reconstruct payload and verify signature
                const payload = JSON.stringify({
                    consumer_id,
                    provider_id,
                    timestamp,
                    body: requestBody,
                });

                const isValid = verifySignature(payload, signature, agentInfo.public_key);
                if (!isValid) {
                    return {
                        webhookResponse: {
                            status: 401,
                            body: { error: 'Invalid signature' },
                        },
                    };
                }
            }

            // Return the verified request to the workflow
            return {
                workflowData: [
                    [
                        {
                            json: {
                                verified: verifySignatures,
                                consumer_id,
                                provider_id,
                                timestamp,
                                body: requestBody,
                                headers: req.headers,
                            },
                        },
                    ],
                ],
            };
        } catch (error: any) {
            return {
                webhookResponse: {
                    status: 500,
                    body: { error: error.message },
                },
            };
        }
    }
}

function verifySignature(
    payload: string,
    signature: string,
    publicKey: string,
): boolean {
    try {
        const verify = createVerify('SHA256');
        verify.update(payload);
        return verify.verify(publicKey, signature, 'base64');
    } catch {
        return false;
    }
}
