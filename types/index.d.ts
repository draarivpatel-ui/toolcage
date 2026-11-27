export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type ErrorCode = string;

export interface ValidationIssue {
    code: ErrorCode;
    message: string;
    path: string;
  }

export type ParameterType = 'any' | 'string' | 'number' | 'integer' | 'boolean' | 'object' | 'array' | 'path' | 'url' | 'command' | 'null';

export interface HostPolicy {
    allow?: readonly string[];
    deny?: readonly string[];
  }

export interface ParameterSpec {
    type: ParameterType;
    required?: boolean;
    nullable?: boolean;
    enum?: readonly JsonValue[];
    minLength?: number;
    maxLength?: number;
    maxBytes?: number;
    pattern?: string;
    min?: number;
    max?: number;
    multipleOf?: number;
    properties?: { readonly [key: string]: ParameterSpec };
    additionalProperties?: boolean;
    items?: ParameterSpec;
    minItems?: number;
    maxItems?: number;
    uniqueItems?: boolean;
    maxProperties?: number;
    maxDepth?: number;
    allowAbsolute?: boolean;
    allowParentTraversal?: boolean;
    allowUnicodeNormalizationBypass?: boolean;
    allowShellOperators?: boolean;
    allowPrivateNetworks?: boolean;
    allowedSchemes?: readonly string[];
    allowedPorts?: readonly number[] | 'default-only' | 'any';
    hostPolicy?: HostPolicy;
    metadata?: JsonObject;
  }

export interface RateLimitPolicy {
    windowMs: number;
    maxCalls: number;
  }

export interface ResultPolicy {
    maxBytes?: number;
    maxDepth?: number;
    blockOnInstruction?: boolean;
    redactSecrets?: boolean;
    removeHiddenUnicode?: boolean;
    sensitiveKeys?: readonly string[];
    customSecretPatterns?: readonly string[];
  }

export interface ToolPolicy {
    description?: string;
    enabled?: boolean;
    parameters?: { readonly [key: string]: ParameterSpec };
    maxCalls?: number;
    rateLimit?: RateLimitPolicy;
    maxBytes?: number;
    maxDepth?: number;
    result?: ResultPolicy;
    metadata?: JsonObject;
  }

export interface BudgetPolicy {
    maxCalls?: number;
    maxBytes?: number;
    windowMs?: number;
    windowMaxCalls?: number;
    duplicateWindowMs?: number;
    maxDuplicates?: number;
  }

export interface ToolCagePolicy {
    version?: 1;
    tools: { readonly [toolName: string]: ToolPolicy };
    allowedTools?: readonly string[];
    deniedTools?: readonly string[];
    allowUnknownTools?: boolean;
    budget?: BudgetPolicy;
    sanitizer?: ResultPolicy;
    metadata?: JsonObject;
  }

export interface PolicyIssue {
    kind: 'error' | 'warning';
    code: string;
    message: string;
    path: string;
  }

export interface PolicyAudit {
    ok: boolean;
    errors: readonly PolicyIssue[];
    warnings: readonly PolicyIssue[];
    summary: {
      tools: number;
      parameters: number;
      errors: number;
      warnings: number;
    };
  }

export interface ValidateSuccess {
    ok: true;
    tool: string;
    normalizedArguments: JsonObject;
    bytes: number;
    depth: number;
    unknownTool: boolean;
  }

export interface ValidateFailure {
    ok: false;
    errors: readonly ValidationIssue[];
    bytes?: number;
    depth?: number;
  }

export type ValidateCallResult = ValidateSuccess | ValidateFailure;

export interface SanitizerFinding {
    code: string;
    path: string;
    message: string;
  }

export interface SanitizeResult {
    action: 'allow' | 'sanitized' | 'blocked';
    ok: boolean;
    value: JsonValue | null;
    findings: readonly SanitizerFinding[];
    removedHidden: number;
    redactedSecrets: number;
    bytes: number;
  }

export interface ExecuteSuccess {
    ok: true;
    value: JsonValue | null;
    action: 'allow' | 'sanitized';
    findings: readonly SanitizerFinding[];
    bytes: number;
    inputHash: string;
    auditHash: string;
  }

export interface ExecuteFailure {
    ok: false;
    error?: {
      code: string;
      message: string;
    };
    errors?: readonly ValidationIssue[];
    findings?: readonly SanitizerFinding[];
    auditHash: string;
  }

export type ExecuteResult = ExecuteSuccess | ExecuteFailure;

export interface AuditEntry {
    sequence: number;
    timestamp: string;
    event: string;
    tool: string | null;
    decision: string | null;
    inputHash: string | null;
    bytes: number;
    durationMs: number;
    details: JsonObject;
    previousHash: string;
    hash: string;
  }

export interface AuditStatistics {
    entries: number;
    bytes: number;
    events: { readonly [event: string]: number };
    digest: string;
  }

export interface BudgetSnapshot {
    calls: number;
    bytes: number;
    remainingCalls: number;
    remainingBytes: number;
    perTool: { readonly [toolName: string]: number };
  }

export interface FirewallOptions {
    now?: () => number;
  }

export type ToolHandler = (args: JsonObject, context: { readonly toolName: string; readonly inputHash: string }) => JsonValue | Promise<JsonValue>;
export type WrappedTool = (args: JsonObject) => Promise<ExecuteResult>;

export class ToolCageError extends Error {
    readonly code: string;
    readonly details?: unknown;
    constructor(code: string, message: string, details?: unknown);
  }

export class AuditTrail {
    constructor(options?: FirewallOptions);
    append(event: string, fields?: { [key: string]: unknown }): AuditEntry;
    entries(): readonly AuditEntry[];
    verify(): boolean;
    digest(): string;
    statistics(): AuditStatistics;
  }

export class CapabilityBudget {
    constructor(config?: BudgetPolicy, options?: FirewallOptions);
    admit(toolName: string, toolPolicy: ToolPolicy, inputHash: string, inputBytes: number): { ok: boolean; code?: string; message?: string };
    complete(toolName: string, outputBytes: number): { ok: boolean; code?: string; message?: string };
    snapshot(): BudgetSnapshot;
  }

export class ToolCage {
    constructor(policy: ToolCagePolicy, options?: FirewallOptions);
    readonly policy: ToolCagePolicy;
    resolveTool(toolName: string): { allowed: boolean; code?: string; message?: string };
    validateCall(toolName: string, args: JsonObject): ValidateCallResult;
    execute(toolName: string, args: JsonObject, handler: ToolHandler): Promise<ExecuteResult>;
    wrapTool(toolName: string, handler: ToolHandler): WrappedTool;
    wrapTools(handlers: { readonly [toolName: string]: ToolHandler }): { readonly [toolName: string]: WrappedTool };
    sanitizeResult(value: JsonValue, toolName?: string): SanitizeResult;
    auditEntries(): readonly AuditEntry[];
    verifyAudit(): boolean;
    auditDigest(): string;
    budgetSnapshot(): BudgetSnapshot;
  }

export function stableStringify(value: JsonValue): string;
export function canonicalHash(value: JsonValue): string;
export function sha256Text(text: string): string;
export function measuredJsonBytes(value: JsonValue): number;
export function maxDepthOf(value: JsonValue): number;
export function parseIpv4(host: string): string | null;
export function parseIpv6(host: string): readonly number[] | null;
export function normalizeIp(host: string): string | null;
export function classifyIp(host: string): string;
export function classifyIpv4(host: string): string;
export function classifyIpv6(host: string): string;
export function isPublicIp(host: string): boolean;
export function splitCommandWords(command: string): readonly string[] | null;
export function guardCommand(value: string, spec: ParameterSpec, path?: string): readonly ValidationIssue[];
export function guardPath(value: string, spec: ParameterSpec, path?: string): readonly ValidationIssue[];
export function guardUrl(value: string, spec: ParameterSpec, path?: string): readonly ValidationIssue[];
export function inspectToolArguments(args: unknown): { ok: boolean; errors: readonly ValidationIssue[]; bytes?: number; depth?: number };
export function validateToolArguments(args: JsonObject, toolSpec: ToolPolicy): ValidateCallResult | { ok: false; errors: readonly ValidationIssue[] };
export function auditPolicy(policy: ToolCagePolicy): PolicyAudit;
export function normalizePolicy(policy: ToolCagePolicy): ToolCagePolicy;
export function sanitizeToolResult(result: JsonValue, options?: ResultPolicy): SanitizeResult;
export function resultLooksDangerous(result: JsonValue): boolean;
export function createFirewall(policy: ToolCagePolicy, options?: FirewallOptions): ToolCage;
export function wrapTool(policy: ToolCagePolicy, toolName: string, handler: ToolHandler, options?: FirewallOptions): WrappedTool;

export const REDACTED_SECRET: '[REDACTED_SECRET]';
export const REDACTED_BLOCK: '[REDACTED_PRIVATE_KEY_BLOCK]';
export const AUDIT_GENESIS_HASH: string;
export const VERSION: '1.0.0';
