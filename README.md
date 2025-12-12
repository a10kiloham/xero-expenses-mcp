# xero-expenses-mcp

MCP (Model Context Protocol) server for Xero accounting. Supports Invoices, Bills, Expenses (Bank Transactions), and Expense Claims with PKCE authentication.

## Features

- **Invoices (ACCREC)** - Create sales invoices to send to customers
- **Bills (ACCPAY)** - Create bills you'll pay later
- **Expenses** - Create "Spend Money" bank transactions for already-paid expenses
- **Expense Claims** - Create receipts and submit expense claims for reimbursement
- **Attachments** - Attach PDFs and images to invoices, bills, expenses, and receipts
- **PKCE Auth** - Desktop app OAuth flow (no client secret required)

## Installation

```bash
npx xero-expenses-mcp
```

Or install globally:

```bash
npm install -g xero-expenses-mcp
```

## Xero App Setup

1. Go to [Xero Developer Portal](https://developer.xero.com/app/manage)
2. Create a new app:
   - **App name**: Your choice (e.g., "Expense Manager")
   - **Integration type**: "Mobile or desktop app" (uses PKCE, no secret needed)
   - **Redirect URI**: `http://localhost:3000/callback`
3. Note your **Client ID**

## Claude Code Configuration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "xero-expenses": {
      "command": "npx",
      "args": ["xero-expenses-mcp"],
      "env": {
        "XERO_CLIENT_ID": "YOUR_CLIENT_ID"
      }
    }
  }
}
```

Or use the CLI:

```bash
claude mcp add xero-expenses -- npx xero-expenses-mcp
```

Then set environment variables in your shell or `.env` file.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `XERO_CLIENT_ID` | Yes | Your Xero app's client ID |
| `XERO_CLIENT_SECRET` | No | Only for Web apps (not PKCE) |
| `XERO_REDIRECT_URI` | No | Default: `http://localhost:3000/callback` |

## Authentication

On first use, the server will open a browser for Xero OAuth. After authenticating, tokens are stored in `~/.xero-mcp/token.json`.

## Available Tools

### Accounts & Contacts
- `xero_list_accounts` - List expense accounts/categories
- `xero_list_bank_accounts` - List bank accounts
- `xero_list_contacts` - Search vendors/contacts
- `xero_list_users` - List organization users (for expense claims)

### Invoices (Accounts Receivable)
- `xero_create_invoice` - Create a sales invoice to send to customers
- `xero_attach_file_to_invoice` - Attach file to an invoice

### Bills (Accounts Payable)
- `xero_create_bill` - Create a bill for future payment
- `xero_attach_file` - Attach file to a bill

### Expenses (Bank Transactions)
- `xero_create_expense` - Create a "Spend Money" transaction
- `xero_attach_file_to_expense` - Attach file to an expense

### Expense Claims (deprecated Feb 2026)
- `xero_create_expense_claim` - Create receipt + expense claim
- `xero_attach_file_to_receipt` - Attach file to a receipt

## Example Usage

In Claude Code:

```
"Create an expense for $45.50 lunch at Cafe Example on 2024-01-15, categorize as Business Meals (account 620)"
```

Claude will use the `xero_create_expense_claim` tool with:
```json
{
  "vendorName": "Cafe Example",
  "amount": 45.50,
  "description": "Lunch",
  "accountCode": "620",
  "date": "2024-01-15"
}
```

## Token Storage

Tokens are stored in `~/.xero-mcp/token.json`. To re-authenticate, delete this file.

## License

MIT
