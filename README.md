# n8n-nodes-amorce

**Connect n8n workflows to LangChain, CrewAI, AutoGPT, and any AI agent — in minutes.**

This package brings cross-framework agent communication to n8n. Discover, call, and receive verified requests from AI agents registered in the Amorce Trust Directory.

## 🔌 Nodes

### Amorce Agent

Send requests to AI agents with cryptographic signing:

| Operation | Description |
|-----------|-------------|
| **Discover** | Look up an agent's info in the Amorce registry |
| **Search** | Find agents by capability (natural language) |
| **Call** | Send a signed request to an agent |

### Amorce Trigger

Receive verified requests from AI agents:

- Automatic signature verification
- Whitelist specific agents
- Returns verified consumer info to your workflow

## 🚀 Installation

### Via n8n Community Nodes

1. Go to **Settings** > **Community Nodes**
2. Click **Install**
3. Enter `n8n-nodes-amorce`
4. Click **Install**

### Manual Installation

```bash
cd ~/.n8n/custom
npm install n8n-nodes-amorce
```

## ⚙️ Configuration

1. **Register your workflow** as an agent at [amorce.io/register](https://amorce.io/register)
2. **Add credentials** in n8n:
   - Directory URL: `https://trust.amorce.io/api/v1`
   - Agent ID: Your registered ID
   - Private Key: Your Ed25519 private key (PEM format)

## 📖 Examples

### Call a LangChain Agent from n8n

```
[Trigger] → [Amorce Agent: Call] → [Process Response]
                    ↓
        Agent ID: langchain-research-agent
        Body: {"query": "Find flights to Paris"}
```

### Receive Requests from CrewAI

```
[Amorce Trigger] → [Your Logic] → [Respond]
        ↓
 Verified request from CrewAI agent
```

### Search for Agents

```
[Manual Trigger] → [Amorce Agent: Search] → [Loop] → [Call each agent]
                           ↓
               Query: "book travel"
```

## 🔐 Security

- All outgoing requests are cryptographically signed
- Incoming requests can be verified against the Amorce registry
- Whitelist specific agents for sensitive workflows

## 🔗 Links

- [Amorce Documentation](https://amorce.io/docs)
- [Trust Directory](https://amorce.io/registry)
- [GitHub](https://github.com/AmorceAATP/n8n-nodes-amorce)

## 📜 License

MIT
