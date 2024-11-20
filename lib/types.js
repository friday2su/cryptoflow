"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoFlowException = void 0;
/**
 * Custom error class for CryptoFlow
 */
class CryptoFlowException extends Error {
    constructor(type, message) {
        super(message);
        this.type = type;
        this.name = 'CryptoFlowException';
    }
}
exports.CryptoFlowException = CryptoFlowException;
