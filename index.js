#!/usr/bin/env node
/**
 * xero-expenses-mcp - MCP server for Xero expense management
 *
 * Supports Bills (ACCPAY), Expenses (Bank Transactions), and Expense Claims
 * Uses PKCE for Desktop app OAuth (no client secret required)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { XeroClient } from "xero-node";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { createServer } from "http";
import { URL } from "url";
import open from "open";
import { basename, join } from "path";
import { homedir } from "os";
import { randomBytes, createHash } from "crypto";

// Store tokens in user's home directory
const TOKEN_DIR = join(homedir(), ".xero-mcp");
const TOKEN_PATH = join(TOKEN_DIR, "token.json");

// PKCE helpers
function generateCodeVerifier() {
  return randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

class XeroExpensesMCP {
  constructor() {
    const redirectUri = process.env.XERO_REDIRECT_URI || "http://localhost:3000/callback";
    const clientSecret = process.env.XERO_CLIENT_SECRET;

    if (!process.env.XERO_CLIENT_ID) {
      console.error("Error: XERO_CLIENT_ID environment variable is required");
      process.exit(1);
    }

    // Support both Web app (with secret) and Desktop app (PKCE, no secret)
    const config = {
      clientId: process.env.XERO_CLIENT_ID,
      redirectUris: [redirectUri],
      scopes: [
        "openid",
        "profile",
        "email",
        "accounting.transactions",
        "accounting.contacts",
        "accounting.settings.read",
        "accounting.attachments",
        "offline_access",
      ],
    };

    // Only add clientSecret if provided (Web app mode)
    // Desktop app uses PKCE - no secret needed
    if (clientSecret) {
      config.clientSecret = clientSecret;
    }

    this.xero = new XeroClient(config);
    this.tenantId = null;

    // Ensure token directory exists
    if (!existsSync(TOKEN_DIR)) {
      mkdirSync(TOKEN_DIR, { recursive: true });
    }
  }

  async loadTokens() {
    if (existsSync(TOKEN_PATH)) {
      const tokens = JSON.parse(readFileSync(TOKEN_PATH, "utf8"));
      this.xero.setTokenSet(tokens);

      const tokenSet = this.xero.readTokenSet();
      if (tokenSet && tokenSet.expired && tokenSet.expired()) {
        await this.xero.refreshToken();
        this.saveTokens();
      }

      const tenants = await this.xero.updateTenants();
      this.tenantId = tenants[0]?.tenantId;
      return true;
    }
    return false;
  }

  saveTokens() {
    const tokenSet = this.xero.readTokenSet();
    if (tokenSet) {
      writeFileSync(TOKEN_PATH, JSON.stringify(tokenSet, null, 2));
    }
  }

  async authenticate() {
    const redirectUri = process.env.XERO_REDIRECT_URI || "http://localhost:3000/callback";
    const clientId = process.env.XERO_CLIENT_ID;
    const clientSecret = process.env.XERO_CLIENT_SECRET;
    const port = 3000;

    // Generate PKCE values
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Build authorization URL
    const scopes = [
      "openid", "profile", "email",
      "accounting.transactions", "accounting.contacts",
      "accounting.settings.read", "accounting.attachments", "offline_access"
    ].join(" ");

    const authUrl = new URL("https://login.xero.com/identity/connect/authorize");
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("scope", scopes);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    return new Promise((resolve, reject) => {
      const server = createServer(async (req, res) => {
        const url = new URL(req.url, `http://localhost:${port}`);

        if (url.pathname === "/callback") {
          const code = url.searchParams.get("code");

          if (code) {
            try {
              // Exchange code for tokens using PKCE
              const tokenUrl = "https://identity.xero.com/connect/token";
              const body = new URLSearchParams({
                grant_type: "authorization_code",
                code: code,
                redirect_uri: redirectUri,
                client_id: clientId,
                code_verifier: codeVerifier,
              });

              // Add client_secret if available (Web app mode)
              if (clientSecret) {
                body.set("client_secret", clientSecret);
              }

              const tokenResponse = await fetch(tokenUrl, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
              });

              if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                throw new Error(`Token exchange failed: ${errorText}`);
              }

              const tokens = await tokenResponse.json();

              // Set tokens on XeroClient
              this.xero.setTokenSet(tokens);
              this.saveTokens();

              const tenants = await this.xero.updateTenants();
              this.tenantId = tenants[0]?.tenantId;

              res.writeHead(200, { "Content-Type": "text/html" });
              res.end("<h1>Authentication successful!</h1><p>You can close this window.</p>");
              server.close();
              resolve(true);
            } catch (error) {
              res.writeHead(500, { "Content-Type": "text/html" });
              res.end(`<h1>Error</h1><p>${error.message}</p>`);
              server.close();
              reject(error);
            }
          }
        }
      });

      server.listen(port, async () => {
        console.error(`Opening browser for Xero authentication on port ${port}...`);
        await open(authUrl.toString());
      });

      setTimeout(() => {
        server.close();
        reject(new Error("Authentication timed out after 5 minutes"));
      }, 300000);
    });
  }

  async ensureAuthenticated() {
    const hasTokens = await this.loadTokens().catch(() => false);
    if (!hasTokens || !this.tenantId) {
      await this.authenticate();
    }
    return true;
  }

  async listAccounts() {
    await this.ensureAuthenticated();
    const response = await this.xero.accountingApi.getAccounts(this.tenantId);
    return response.body.accounts
      .filter(a => a.status === "ACTIVE")
      .map(a => ({
        code: a.code,
        name: a.name,
        type: a.type,
        class: a.class,
        accountId: a.accountID,
      }));
  }

  async listBankAccounts() {
    await this.ensureAuthenticated();
    const response = await this.xero.accountingApi.getAccounts(this.tenantId);
    return response.body.accounts
      .filter(a => a.status === "ACTIVE" && a.type === "BANK")
      .map(a => ({
        accountId: a.accountID,
        code: a.code,
        name: a.name,
      }));
  }

  async listContacts(searchTerm) {
    await this.ensureAuthenticated();
    const where = searchTerm ? `Name.Contains("${searchTerm}")` : undefined;
    const response = await this.xero.accountingApi.getContacts(
      this.tenantId,
      undefined,
      where,
      undefined,
      undefined,
      undefined,
      undefined,
      20
    );
    return response.body.contacts.map(c => ({
      contactId: c.contactID,
      name: c.name,
      email: c.emailAddress,
    }));
  }

  async createContact(name, email) {
    await this.ensureAuthenticated();
    const contact = { name, emailAddress: email };
    const response = await this.xero.accountingApi.createContacts(this.tenantId, { contacts: [contact] });
    const created = response.body.contacts[0];
    return { contactId: created.contactID, name: created.name };
  }

  async createBill({ vendorName, vendorEmail, amount, description, accountCode, date, dueDate, reference }) {
    await this.ensureAuthenticated();

    // Find or create contact
    let contacts = await this.listContacts(vendorName);
    let contact = contacts.find(c => c.name.toLowerCase() === vendorName.toLowerCase());

    if (!contact) {
      contact = await this.createContact(vendorName, vendorEmail || undefined);
    }

    // Create the bill (ACCPAY invoice)
    const bill = {
      type: "ACCPAY",
      contact: { contactID: contact.contactId },
      date: date || new Date().toISOString().split("T")[0],
      dueDate: dueDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
      reference: reference || undefined,
      lineItems: [
        {
          description: description || "Expense",
          quantity: 1,
          unitAmount: amount,
          accountCode: accountCode || "400", // Default expense account
        },
      ],
      status: "DRAFT",
    };

    const response = await this.xero.accountingApi.createInvoices(this.tenantId, { invoices: [bill] });
    const created = response.body.invoices[0];

    return {
      invoiceId: created.invoiceID,
      invoiceNumber: created.invoiceNumber,
      vendor: created.contact.name,
      total: created.total,
      status: created.status,
      date: created.date,
    };
  }

  async attachFileToBill(invoiceId, filePath) {
    await this.ensureAuthenticated();

    const fileName = basename(filePath);
    const fileContent = readFileSync(filePath);

    // Determine mime type from extension
    const ext = fileName.split('.').pop().toLowerCase();
    const mimeTypes = {
      'pdf': 'application/pdf',
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
    };
    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    const response = await this.xero.accountingApi.createInvoiceAttachmentByFileName(
      this.tenantId,
      invoiceId,
      fileName,
      fileContent,
      true, // includeOnline
      mimeType
    );

    return {
      attachmentId: response.body.attachments[0]?.attachmentID,
      fileName: fileName,
      success: true,
    };
  }

  async createExpense({ vendorName, vendorEmail, amount, description, accountCode, date, reference, bankAccountId }) {
    await this.ensureAuthenticated();

    // Find or create contact
    let contacts = await this.listContacts(vendorName);
    let contact = contacts.find(c => c.name.toLowerCase() === vendorName.toLowerCase());

    if (!contact) {
      contact = await this.createContact(vendorName, vendorEmail || undefined);
    }

    // Get bank account - use provided or get first available
    let bankAccount;
    if (bankAccountId) {
      bankAccount = { accountID: bankAccountId };
    } else {
      const bankAccounts = await this.listBankAccounts();
      if (bankAccounts.length === 0) {
        throw new Error("No bank accounts found in Xero. Please create a bank account first.");
      }
      bankAccount = { accountID: bankAccounts[0].accountId };
    }

    // Create the expense (Spend Money = BankTransaction with type SPEND)
    const expense = {
      type: "SPEND",
      contact: { contactID: contact.contactId },
      bankAccount: bankAccount,
      date: date || new Date().toISOString().split("T")[0],
      reference: reference || undefined,
      lineItems: [
        {
          description: description || "Expense",
          quantity: 1,
          unitAmount: amount,
          accountCode: accountCode || "400",
        },
      ],
      status: "AUTHORISED",
    };

    const response = await this.xero.accountingApi.createBankTransactions(this.tenantId, { bankTransactions: [expense] });
    const created = response.body.bankTransactions[0];

    return {
      bankTransactionId: created.bankTransactionID,
      vendor: created.contact.name,
      total: created.total,
      status: created.status,
      date: created.date,
      bankAccount: created.bankAccount?.name,
    };
  }

  async attachFileToExpense(bankTransactionId, filePath) {
    await this.ensureAuthenticated();

    const fileName = basename(filePath);
    const fileContent = readFileSync(filePath);

    // Determine mime type from extension
    const ext = fileName.split('.').pop().toLowerCase();
    const mimeTypes = {
      'pdf': 'application/pdf',
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
    };
    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    const response = await this.xero.accountingApi.createBankTransactionAttachmentByFileName(
      this.tenantId,
      bankTransactionId,
      fileName,
      fileContent,
      mimeType
    );

    return {
      attachmentId: response.body.attachments[0]?.attachmentID,
      fileName: fileName,
      success: true,
    };
  }

  // Expense Claims functionality (deprecated Feb 2026 but still works)

  async listUsers() {
    await this.ensureAuthenticated();
    const response = await this.xero.accountingApi.getUsers(this.tenantId);
    return response.body.users.map(u => ({
      userId: u.userID,
      firstName: u.firstName,
      lastName: u.lastName,
      email: u.emailAddress,
      isSubscriber: u.isSubscriber,
    }));
  }

  async createReceipt({ vendorName, vendorEmail, amount, description, accountCode, date, reference, userId }) {
    await this.ensureAuthenticated();

    // Find or create contact
    let contacts = await this.listContacts(vendorName);
    let contact = contacts.find(c => c.name.toLowerCase() === vendorName.toLowerCase());

    if (!contact) {
      contact = await this.createContact(vendorName, vendorEmail || undefined);
    }

    // Get the user for the receipt
    let user;
    if (userId) {
      user = { userID: userId };
    } else {
      // Get first user (usually the org owner)
      const users = await this.listUsers();
      if (users.length === 0) {
        throw new Error("No users found in Xero organization");
      }
      user = { userID: users[0].userId };
    }

    const receipt = {
      contact: { contactID: contact.contactId },
      user: user,
      date: date || new Date().toISOString().split("T")[0],
      reference: reference || undefined,
      lineItems: [
        {
          description: description || "Expense",
          quantity: 1,
          unitAmount: amount,
          accountCode: accountCode || "400",
        },
      ],
      status: "DRAFT",
    };

    const response = await this.xero.accountingApi.createReceipt(this.tenantId, { receipts: [receipt] });
    const created = response.body.receipts[0];

    return {
      receiptId: created.receiptID,
      receiptNumber: created.receiptNumber,
      vendor: created.contact?.name,
      total: created.total,
      status: created.status,
      date: created.date,
      userId: created.user?.userID,
    };
  }

  async createExpenseClaim({ receiptIds, userId }) {
    await this.ensureAuthenticated();

    // Get user
    let user;
    if (userId) {
      user = { userID: userId };
    } else {
      const users = await this.listUsers();
      if (users.length === 0) {
        throw new Error("No users found in Xero organization");
      }
      user = { userID: users[0].userId };
    }

    // Build receipts array
    const receipts = receiptIds.map(id => ({ receiptID: id }));

    const expenseClaim = {
      user: user,
      receipts: receipts,
      status: "SUBMITTED",
    };

    const response = await this.xero.accountingApi.createExpenseClaims(
      this.tenantId,
      { expenseClaims: [expenseClaim] }
    );
    const created = response.body.expenseClaims[0];

    return {
      expenseClaimId: created.expenseClaimID,
      status: created.status,
      total: created.total,
      userId: created.user?.userID,
      receipts: created.receipts?.map(r => r.receiptID),
    };
  }

  async createExpenseClaimFromReceipt({ vendorName, vendorEmail, amount, description, accountCode, date, reference, userId }) {
    // Convenience method: creates receipt and expense claim in one go
    const receipt = await this.createReceipt({
      vendorName, vendorEmail, amount, description, accountCode, date, reference, userId
    });

    const claim = await this.createExpenseClaim({
      receiptIds: [receipt.receiptId],
      userId: userId,
    });

    return {
      expenseClaimId: claim.expenseClaimId,
      receiptId: receipt.receiptId,
      vendor: receipt.vendor,
      total: receipt.total,
      status: claim.status,
      date: receipt.date,
    };
  }

  async createInvoice({ customerName, customerEmail, amount, description, accountCode, date, dueDate, reference }) {
    await this.ensureAuthenticated();

    // Find or create contact
    let contacts = await this.listContacts(customerName);
    let contact = contacts.find(c => c.name.toLowerCase() === customerName.toLowerCase());

    if (!contact) {
      contact = await this.createContact(customerName, customerEmail || undefined);
    }

    // Create the invoice (ACCREC - accounts receivable)
    const invoice = {
      type: "ACCREC",
      contact: { contactID: contact.contactId },
      date: date || new Date().toISOString().split("T")[0],
      dueDate: dueDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
      reference: reference || undefined,
      lineItems: [
        {
          description: description || "Services",
          quantity: 1,
          unitAmount: amount,
          accountCode: accountCode || "200", // Default revenue account
        },
      ],
      status: "DRAFT",
    };

    const response = await this.xero.accountingApi.createInvoices(this.tenantId, { invoices: [invoice] });
    const created = response.body.invoices[0];

    return {
      invoiceId: created.invoiceID,
      invoiceNumber: created.invoiceNumber,
      customer: created.contact.name,
      total: created.total,
      status: created.status,
      date: created.date,
      dueDate: created.dueDate,
    };
  }

  async attachFileToInvoice(invoiceId, filePath) {
    // Same as attachFileToBill - invoices and bills use same attachment API
    return this.attachFileToBill(invoiceId, filePath);
  }

  async attachFileToReceipt(receiptId, filePath) {
    await this.ensureAuthenticated();

    const fileName = basename(filePath);
    const fileContent = readFileSync(filePath);

    const ext = fileName.split('.').pop().toLowerCase();
    const mimeTypes = {
      'pdf': 'application/pdf',
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
    };
    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    // Generate unique idempotency key to avoid conflicts
    const idempotencyKey = `receipt-${receiptId}-${Date.now()}-${Math.random().toString(36).slice(2)}`;

    const response = await this.xero.accountingApi.createReceiptAttachmentByFileName(
      this.tenantId,
      receiptId,
      fileName,
      fileContent,
      idempotencyKey,
      { headers: { 'Content-Type': mimeType } }
    );

    return {
      attachmentId: response.body.attachments[0]?.attachmentID,
      fileName: fileName,
      success: true,
    };
  }
}

// MCP Server setup
const xeroExpenses = new XeroExpensesMCP();

const server = new Server(
  { name: "xero-expenses-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "xero_list_accounts",
      description: "List available Xero accounts/categories for expenses",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "xero_list_bank_accounts",
      description: "List available Xero bank accounts for expenses",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "xero_list_contacts",
      description: "Search for vendors/contacts in Xero",
      inputSchema: {
        type: "object",
        properties: {
          search: { type: "string", description: "Search term for vendor name" },
        },
      },
    },
    {
      name: "xero_create_bill",
      description: "Create a bill (accounts payable) in Xero - use for invoices you'll pay later",
      inputSchema: {
        type: "object",
        properties: {
          vendorName: { type: "string", description: "Name of the vendor" },
          vendorEmail: { type: "string", description: "Email of the vendor (optional)" },
          amount: { type: "number", description: "Total amount of the expense" },
          description: { type: "string", description: "Description of the expense" },
          accountCode: { type: "string", description: "Xero account code (e.g., '400' for expenses)" },
          date: { type: "string", description: "Invoice date (YYYY-MM-DD)" },
          dueDate: { type: "string", description: "Due date (YYYY-MM-DD)" },
          reference: { type: "string", description: "Reference number from the invoice" },
        },
        required: ["vendorName", "amount", "description"],
      },
    },
    {
      name: "xero_create_expense",
      description: "Create a spend money transaction (direct expense) in Xero - use for already-paid expenses like receipts",
      inputSchema: {
        type: "object",
        properties: {
          vendorName: { type: "string", description: "Name of the vendor" },
          vendorEmail: { type: "string", description: "Email of the vendor (optional)" },
          amount: { type: "number", description: "Total amount of the expense" },
          description: { type: "string", description: "Description of the expense" },
          accountCode: { type: "string", description: "Xero expense account code (e.g., '620' for meals)" },
          date: { type: "string", description: "Transaction date (YYYY-MM-DD)" },
          reference: { type: "string", description: "Reference number from the receipt" },
          bankAccountId: { type: "string", description: "Xero bank account ID (optional, uses first available if not specified)" },
        },
        required: ["vendorName", "amount", "description"],
      },
    },
    {
      name: "xero_attach_file",
      description: "Attach a file (PDF, image) to an existing Xero bill",
      inputSchema: {
        type: "object",
        properties: {
          invoiceId: { type: "string", description: "The Xero invoice/bill ID" },
          filePath: { type: "string", description: "Path to the file to attach" },
        },
        required: ["invoiceId", "filePath"],
      },
    },
    {
      name: "xero_attach_file_to_expense",
      description: "Attach a file (PDF, image) to an existing Xero expense (bank transaction)",
      inputSchema: {
        type: "object",
        properties: {
          bankTransactionId: { type: "string", description: "The Xero bank transaction ID" },
          filePath: { type: "string", description: "Path to the file to attach" },
        },
        required: ["bankTransactionId", "filePath"],
      },
    },
    {
      name: "xero_list_users",
      description: "List users in the Xero organization (for expense claims)",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "xero_create_expense_claim",
      description: "Create an expense claim for reimbursement - creates a receipt and submits it as an expense claim (deprecated Feb 2026)",
      inputSchema: {
        type: "object",
        properties: {
          vendorName: { type: "string", description: "Name of the vendor" },
          vendorEmail: { type: "string", description: "Email of the vendor (optional)" },
          amount: { type: "number", description: "Total amount of the expense" },
          description: { type: "string", description: "Description of the expense" },
          accountCode: { type: "string", description: "Xero expense account code (e.g., '620' for meals)" },
          date: { type: "string", description: "Receipt date (YYYY-MM-DD)" },
          reference: { type: "string", description: "Reference number from the receipt" },
          userId: { type: "string", description: "Xero user ID to claim as (optional, uses first user if not specified)" },
        },
        required: ["vendorName", "amount", "description"],
      },
    },
    {
      name: "xero_attach_file_to_receipt",
      description: "Attach a file (PDF, image) to an existing Xero receipt",
      inputSchema: {
        type: "object",
        properties: {
          receiptId: { type: "string", description: "The Xero receipt ID" },
          filePath: { type: "string", description: "Path to the file to attach" },
        },
        required: ["receiptId", "filePath"],
      },
    },
    {
      name: "xero_create_invoice",
      description: "Create a sales invoice (accounts receivable) in Xero - use for invoices you send to customers",
      inputSchema: {
        type: "object",
        properties: {
          customerName: { type: "string", description: "Name of the customer" },
          customerEmail: { type: "string", description: "Email of the customer (optional)" },
          amount: { type: "number", description: "Total amount of the invoice" },
          description: { type: "string", description: "Description of the goods/services" },
          accountCode: { type: "string", description: "Xero revenue account code (e.g., '200' for sales)" },
          date: { type: "string", description: "Invoice date (YYYY-MM-DD)" },
          dueDate: { type: "string", description: "Due date (YYYY-MM-DD)" },
          reference: { type: "string", description: "Reference or PO number" },
        },
        required: ["customerName", "amount", "description"],
      },
    },
    {
      name: "xero_attach_file_to_invoice",
      description: "Attach a file (PDF, image) to an existing Xero invoice",
      inputSchema: {
        type: "object",
        properties: {
          invoiceId: { type: "string", description: "The Xero invoice ID" },
          filePath: { type: "string", description: "Path to the file to attach" },
        },
        required: ["invoiceId", "filePath"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "xero_list_accounts": {
        const accounts = await xeroExpenses.listAccounts();
        const expenseAccounts = accounts.filter(a => a.class === "EXPENSE" || a.type === "EXPENSE");
        return {
          content: [{ type: "text", text: JSON.stringify(expenseAccounts, null, 2) }],
        };
      }

      case "xero_list_bank_accounts": {
        const accounts = await xeroExpenses.listBankAccounts();
        return {
          content: [{ type: "text", text: JSON.stringify(accounts, null, 2) }],
        };
      }

      case "xero_list_contacts": {
        const contacts = await xeroExpenses.listContacts(args.search);
        return {
          content: [{ type: "text", text: JSON.stringify(contacts, null, 2) }],
        };
      }

      case "xero_create_bill": {
        const result = await xeroExpenses.createBill(args);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_create_expense": {
        const result = await xeroExpenses.createExpense(args);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_attach_file": {
        const result = await xeroExpenses.attachFileToBill(args.invoiceId, args.filePath);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_attach_file_to_expense": {
        const result = await xeroExpenses.attachFileToExpense(args.bankTransactionId, args.filePath);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_list_users": {
        const users = await xeroExpenses.listUsers();
        return {
          content: [{ type: "text", text: JSON.stringify(users, null, 2) }],
        };
      }

      case "xero_create_expense_claim": {
        const result = await xeroExpenses.createExpenseClaimFromReceipt(args);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_attach_file_to_receipt": {
        const result = await xeroExpenses.attachFileToReceipt(args.receiptId, args.filePath);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_create_invoice": {
        const result = await xeroExpenses.createInvoice(args);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "xero_attach_file_to_invoice": {
        const result = await xeroExpenses.attachFileToInvoice(args.invoiceId, args.filePath);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
    }
  } catch (error) {
    const errorMsg = error.response?.body
      ? JSON.stringify(error.response.body, null, 2)
      : error.message || JSON.stringify(error, null, 2);
    return {
      content: [{ type: "text", text: `Error: ${errorMsg}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
