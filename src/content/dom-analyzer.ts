/**
 * VaultGuard DOM Analyzer
 * Analyzes page DOM for security issues
 */

export interface DOMAnalysisResult {
  scripts: string[];
  inlineScripts: string[];
  externalScripts: string[];
  forms: FormInfo[];
  inputs: InputInfo[];
  links: LinkInfo[];
  iframes: IframeInfo[];
  html: string;
}

export interface FormInfo {
  action: string;
  method: string;
  hasPasswordField: boolean;
  isSecure: boolean;
}

export interface InputInfo {
  type: string;
  name: string;
  hasAutocomplete: boolean;
  autocompleteValue: string;
}

export interface LinkInfo {
  href: string;
  isExternal: boolean;
  hasNoopener: boolean;
  hasNoreferrer: boolean;
}

export interface IframeInfo {
  src: string;
  sandbox: string | null;
  isThirdParty: boolean;
}

export class DOMAnalyzer {
  /**
   * Analyze the current page DOM
   */
  analyze(): DOMAnalysisResult {
    return {
      scripts: this.extractAllScripts(),
      inlineScripts: this.extractInlineScripts(),
      externalScripts: this.extractExternalScripts(),
      forms: this.analyzeForms(),
      inputs: this.analyzeInputs(),
      links: this.analyzeLinks(),
      iframes: this.analyzeIframes(),
      html: this.getRelevantHTML(),
    };
  }
  
  /**
   * Extract all script contents
   */
  private extractAllScripts(): string[] {
    const scripts: string[] = [];
    
    // Inline scripts
    document.querySelectorAll('script:not([src])').forEach((script) => {
      if (script.textContent) {
        scripts.push(script.textContent);
      }
    });
    
    return scripts;
  }
  
  /**
   * Extract inline script contents
   */
  private extractInlineScripts(): string[] {
    const scripts: string[] = [];
    
    document.querySelectorAll('script:not([src])').forEach((script) => {
      if (script.textContent) {
        scripts.push(script.textContent);
      }
    });
    
    // Also check for inline event handlers
    const eventAttributes = [
      'onclick',
      'onload',
      'onerror',
      'onsubmit',
      'onchange',
      'onmouseover',
    ];
    
    eventAttributes.forEach((attr) => {
      document.querySelectorAll(`[${attr}]`).forEach((el) => {
        const value = el.getAttribute(attr);
        if (value) {
          scripts.push(value);
        }
      });
    });
    
    return scripts;
  }
  
  /**
   * Extract external script URLs
   */
  private extractExternalScripts(): string[] {
    const scripts: string[] = [];
    
    document.querySelectorAll('script[src]').forEach((script) => {
      const src = script.getAttribute('src');
      if (src) {
        scripts.push(src);
      }
    });
    
    return scripts;
  }
  
  /**
   * Analyze forms for security issues
   */
  private analyzeForms(): FormInfo[] {
    const forms: FormInfo[] = [];
    
    document.querySelectorAll('form').forEach((form) => {
      const action = form.action || window.location.href;
      const method = (form.method || 'GET').toUpperCase();
      const hasPasswordField = form.querySelector('input[type="password"]') !== null;
      const isSecure = action.startsWith('https://');
      
      forms.push({
        action,
        method,
        hasPasswordField,
        isSecure,
      });
    });
    
    return forms;
  }
  
  /**
   * Analyze input fields
   */
  private analyzeInputs(): InputInfo[] {
    const inputs: InputInfo[] = [];
    
    document.querySelectorAll('input').forEach((input) => {
      inputs.push({
        type: input.type || 'text',
        name: input.name || '',
        hasAutocomplete: input.hasAttribute('autocomplete'),
        autocompleteValue: input.getAttribute('autocomplete') || '',
      });
    });
    
    return inputs;
  }
  
  /**
   * Analyze links for security issues
   */
  private analyzeLinks(): LinkInfo[] {
    const links: LinkInfo[] = [];
    const currentOrigin = window.location.origin;
    
    document.querySelectorAll('a[href]').forEach((link) => {
      const href = link.getAttribute('href') || '';
      const rel = link.getAttribute('rel') || '';
      
      let isExternal = false;
      try {
        const url = new URL(href, window.location.origin);
        isExternal = url.origin !== currentOrigin;
      } catch {
        // Invalid URL
      }
      
      links.push({
        href,
        isExternal,
        hasNoopener: rel.includes('noopener'),
        hasNoreferrer: rel.includes('noreferrer'),
      });
    });
    
    return links;
  }
  
  /**
   * Analyze iframes
   */
  private analyzeIframes(): IframeInfo[] {
    const iframes: IframeInfo[] = [];
    const currentOrigin = window.location.origin;
    
    document.querySelectorAll('iframe').forEach((iframe) => {
      const src = iframe.src || '';
      const sandbox = iframe.getAttribute('sandbox');
      
      let isThirdParty = false;
      try {
        const url = new URL(src, window.location.origin);
        isThirdParty = url.origin !== currentOrigin;
      } catch {
        // Invalid URL
      }
      
      iframes.push({
        src,
        sandbox,
        isThirdParty,
      });
    });
    
    return iframes;
  }
  
  /**
   * Get relevant HTML for analysis (limited to avoid performance issues)
   */
  private getRelevantHTML(): string {
    // Get head content (often contains configs)
    const head = document.head?.innerHTML || '';
    
    // Get data attributes that might contain sensitive info
    const dataElements: string[] = [];
    document.querySelectorAll('[data-api-key], [data-token], [data-secret], [data-config]').forEach((el) => {
      dataElements.push(el.outerHTML);
    });
    
    // Combine but limit size
    const combined = head + dataElements.join('');
    return combined.slice(0, 100000); // Limit to 100KB
  }
}