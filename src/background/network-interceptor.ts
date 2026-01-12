/**
 * VaultGuard Network Interceptor
 * Captures and analyzes network requests
 */

import type { NetworkRequest, NetworkResponse } from '../types';
import { logger } from '../utils/logger';
import { generateId } from '../utils/crypto';

interface CapturedRequest {
  request: NetworkRequest;
  responseHeaders?: Record<string, string>;
}

export class NetworkInterceptor {
  private requests: Map<string, CapturedRequest> = new Map();
  private maxRequests = 1000;

  /**
   * Capture an outgoing request
   */
  captureRequest(details: chrome.webRequest.WebRequestBodyDetails): void {
    const request: NetworkRequest = {
      id: details.requestId,
      url: details.url,
      method: details.method,
      headers: {}, // Headers captured separately
      body: this.extractBody(details),
      timestamp: details.timeStamp,
      tabId: details.tabId,
      type: details.type,
    };

    this.requests.set(details.requestId, { request });

    // Cleanup old requests
    if (this.requests.size > this.maxRequests) {
      const oldest = Array.from(this.requests.keys()).slice(0, 100);
      oldest.forEach((id) => this.requests.delete(id));
    }

    logger.debug('NetworkInterceptor', `Captured request: ${details.url}`);
  }

  /**
   * Capture response headers
   */
  captureResponseHeaders(
    details: chrome.webRequest.WebResponseHeadersDetails
  ): void {
    const existing = this.requests.get(details.requestId);

    if (existing) {
      const headers: Record<string, string> = {};

      for (const header of details.responseHeaders ?? []) {
        if (header.name && header.value) {
          headers[header.name] = header.value;
        }
      }

      existing.responseHeaders = headers;

      logger.debug('NetworkInterceptor', `Captured response headers: ${details.url}`);
    }
  }

  /**
   * Get captured request by ID
   */
  getRequest(requestId: string): CapturedRequest | undefined {
    return this.requests.get(requestId);
  }

  /**
   * Get all requests for a tab
   */
  getRequestsForTab(tabId: number): CapturedRequest[] {
    return Array.from(this.requests.values()).filter(
      (r) => r.request.tabId === tabId
    );
  }

  /**
   * Clear requests for a tab
   */
  clearTab(tabId: number): void {
    for (const [id, captured] of this.requests.entries()) {
      if (captured.request.tabId === tabId) {
        this.requests.delete(id);
      }
    }
  }

  /**
   * Clear all requests
   */
  clear(): void {
    this.requests.clear();
  }

  /**
   * Extract request body
   */
  private extractBody(
    details: chrome.webRequest.WebRequestBodyDetails
  ): string | undefined {
    if (!details.requestBody) return undefined;

    if (details.requestBody.raw) {
      const decoder = new TextDecoder();
      const parts = details.requestBody.raw
        .map((part) => {
          if (part.bytes) {
            return decoder.decode(part.bytes);
          }
          return '';
        })
        .filter(Boolean);

      return parts.join('');
    }

    if (details.requestBody.formData) {
      return JSON.stringify(details.requestBody.formData);
    }

    return undefined;
  }

  /**
   * Get statistics
   */
  getStats(): { totalRequests: number; byType: Record<string, number> } {
    const byType: Record<string, number> = {};

    for (const { request } of this.requests.values()) {
      byType[request.type] = (byType[request.type] ?? 0) + 1;
    }

    return {
      totalRequests: this.requests.size,
      byType,
    };
  }
}