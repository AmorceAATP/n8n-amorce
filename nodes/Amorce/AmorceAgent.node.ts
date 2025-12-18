import {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    NodeOperationError,
} from 'n8n-workflow';
import { createSign } from 'crypto';

export class AmorceAgent implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'Amorce Agent',
        name: 'amorceAgent',
        icon: 'file:amorce.svg',
        group: ['transform'],
        version: 1,
        subtitle: '={{$parameter["operation"]}}',
        description: 'Interact with AI agents via the Amorce Trust Protocol',
        defaults: {
            name: 'Amorce Agent',
        },
        inputs: ['main'],
        outputs: ['main'],
        credentials: [
            {
                name: 'amorceApi',
                required: true,
            },
        ],
        properties: [
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                options: [
                    {
                        name: 'Discover Agent',
                        value: 'discover',
                        description: 'Find an agent in the Amorce registry',
                        action: 'Discover an agent',
                    },
                    {
                        name: 'Call Agent',
                        value: 'call',
                        description: 'Send a signed request to an agent',
                        action: 'Call an agent',
                    },
                    {
                        name: 'Search Agents',
                        value: 'search',
                        description: 'Search for agents by capability or name',
                        action: 'Search agents',
                    },
                ],
                default: 'call',
            },
            // Discover operation
            {
                displayName: 'Agent ID',
                name: 'targetAgentId',
                type: 'string',
                default: '',
                placeholder: 'langchain-research-agent',
                description: 'The ID of the agent to discover or call',
                displayOptions: {
                    show: {
                        operation: ['discover', 'call'],
                    },
                },
            },
            // Search operation
            {
                displayName: 'Search Query',
                name: 'searchQuery',
                type: 'string',
                default: '',
                placeholder: 'book flights, process payments',
                description: 'Natural language query to find agents',
                displayOptions: {
                    show: {
                        operation: ['search'],
                    },
                },
            },
            // Call operation
            {
                displayName: 'Request Body',
                name: 'requestBody',
                type: 'json',
                default: '{}',
                placeholder: '{"intent": "book_flight", "destination": "Paris"}',
                description: 'The request payload to send to the agent',
                displayOptions: {
                    show: {
                        operation: ['call'],
                    },
                },
            },
            {
                displayName: 'Timeout (ms)',
                name: 'timeout',
                type: 'number',
                default: 30000,
                description: 'Request timeout in milliseconds',
                displayOptions: {
                    show: {
                        operation: ['call'],
                    },
                },
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();
        const returnData: INodeExecutionData[] = [];
        const credentials = await this.getCredentials('amorceApi');

        const directoryUrl = credentials.directoryUrl as string;
        const agentId = credentials.agentId as string;
        const privateKey = credentials.privateKey as string;

        for (let i = 0; i < items.length; i++) {
            try {
                const operation = this.getNodeParameter('operation', i) as string;

                if (operation === 'discover') {
                    const targetAgentId = this.getNodeParameter('targetAgentId', i) as string;

                    // Lookup agent in directory
                    const response = await this.helpers.request({
                        method: 'GET',
                        url: `${directoryUrl}/v1/agents/${encodeURIComponent(targetAgentId)}`,
                        json: true,
                    });

                    returnData.push({
                        json: {
                            success: true,
                            agent: response,
                        },
                    });
                } else if (operation === 'search') {
                    const searchQuery = this.getNodeParameter('searchQuery', i) as string;

                    // Search agents via ANS
                    const response = await this.helpers.request({
                        method: 'GET',
                        url: `${directoryUrl}/v1/ans/search?q=${encodeURIComponent(searchQuery)}`,
                        json: true,
                    });

                    returnData.push({
                        json: {
                            success: true,
                            results: response.results || response,
                        },
                    });
                } else if (operation === 'call') {
                    const targetAgentId = this.getNodeParameter('targetAgentId', i) as string;
                    const requestBody = this.getNodeParameter('requestBody', i) as string;
                    const timeout = this.getNodeParameter('timeout', i) as number;

                    // First, discover the agent to get its endpoint
                    const agentInfo = await this.helpers.request({
                        method: 'GET',
                        url: `${directoryUrl}/v1/agents/${encodeURIComponent(targetAgentId)}`,
                        json: true,
                    });

                    if (!agentInfo.endpoint) {
                        throw new NodeOperationError(
                            this.getNode(),
                            `Agent ${targetAgentId} has no endpoint registered`,
                        );
                    }

                    // Parse request body
                    let body: object;
                    try {
                        body = typeof requestBody === 'string' ? JSON.parse(requestBody) : requestBody;
                    } catch (e) {
                        throw new NodeOperationError(
                            this.getNode(),
                            'Invalid JSON in request body',
                        );
                    }

                    // Create signed transaction
                    const timestamp = new Date().toISOString();
                    const payload = {
                        consumer_id: agentId,
                        provider_id: targetAgentId,
                        timestamp,
                        body,
                    };

                    const payloadString = JSON.stringify(payload);
                    const signature = signPayload(payloadString, privateKey);

                    // Send to orchestrator or directly to agent
                    const response = await this.helpers.request({
                        method: 'POST',
                        url: agentInfo.endpoint,
                        body: {
                            ...payload,
                            signature,
                        },
                        json: true,
                        timeout,
                    });

                    returnData.push({
                        json: {
                            success: true,
                            response,
                            transaction: {
                                consumer: agentId,
                                provider: targetAgentId,
                                timestamp,
                            },
                        },
                    });
                }
            } catch (error: any) {
                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            success: false,
                            error: error.message,
                        },
                    });
                    continue;
                }
                throw new NodeOperationError(this.getNode(), error.message, { itemIndex: i });
            }
        }

        return [returnData];
    }
}

function signPayload(payload: string, privateKey: string): string {
    try {
        const sign = createSign('SHA256');
        sign.update(payload);
        return sign.sign(privateKey, 'base64');
    } catch (error: any) {
        throw new Error(`Failed to sign payload: ${error.message}`);
    }
}
