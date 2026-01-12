/**
 * VaultGuard Message Router
 * Handles inter-component messaging
 */

import type { Message, MessageType } from '../types';
import { logger } from '../utils/logger';

type MessageHandler = (message: Message, sender: chrome.runtime.MessageSender) => Promise<unknown>;

export class MessageRouter {
  private handlers: Map<MessageType, MessageHandler[]> = new Map();
  
  /**
   * Register a handler for a message type
   */
  on(type: MessageType, handler: MessageHandler): void {
    const existing = this.handlers.get(type) ?? [];
    existing.push(handler);
    this.handlers.set(type, existing);
  }
  
  /**
   * Remove a handler for a message type
   */
  off(type: MessageType, handler: MessageHandler): void {
    const existing = this.handlers.get(type) ?? [];
    const index = existing.indexOf(handler);
    if (index > -1) {
      existing.splice(index, 1);
    }
  }
  
  /**
   * Route a message to its handlers
   */
  async route(message: Message, sender: chrome.runtime.MessageSender): Promise<unknown[]> {
    const handlers = this.handlers.get(message.type) ?? [];
    
    if (handlers.length === 0) {
      logger.warn('MessageRouter', `No handlers for message type: ${message.type}`);
      return [];
    }
    
    const results = await Promise.all(
      handlers.map(async (handler) => {
        try {
          return await handler(message, sender);
        } catch (error) {
          logger.error('MessageRouter', `Handler error for ${message.type}`, error);
          return null;
        }
      })
    );
    
    return results;
  }
  
  /**
   * Send a message to a specific tab
   */
  async sendToTab<T>(tabId: number, message: Message): Promise<T | null> {
    try {
      const response = await chrome.tabs.sendMessage(tabId, message);
      return response as T;
    } catch (error) {
      logger.error('MessageRouter', `Failed to send to tab ${tabId}`, error);
      return null;
    }
  }
  
  /**
   * Send a message to all tabs
   */
  async broadcast(message: Message): Promise<void> {
    const tabs = await chrome.tabs.query({});
    
    await Promise.all(
      tabs.map((tab) => {
        if (tab.id) {
          return this.sendToTab(tab.id, message).catch(() => null);
        }
        return Promise.resolve();
      })
    );
  }
  
  /**
   * Create a typed message
   */
  createMessage<T>(type: MessageType, payload?: T, tabId?: number): Message<T> {
    return {
      type,
      payload,
      tabId,
      timestamp: Date.now(),
    };
  }
}