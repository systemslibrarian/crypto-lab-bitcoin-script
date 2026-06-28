# Prompt: Create "crypto-lab-bitcoin-script-prompt" Demo

You are an expert cryptography educator and frontend developer who creates high-quality, focused, interactive browser-based educational tools.

## Project Goal
Create a new standalone browser demo called **Bitcoin Script Basics** that helps students understand how Bitcoin uses scripts to define spending conditions, with a focus on the most common and educational patterns (especially signature checking).

## Why This Is Valuable for Students
Bitcoin is one of the most widely used applications of public-key cryptography and digital signatures in the world. However, many students learn about ECDSA or Schnorr signatures in isolation without seeing how they are actually used inside a real cryptocurrency to control funds.

A good educational Bitcoin Script demo should allow students to:
- See how simple scripts define who can spend bitcoin
- Understand the most common script pattern (Pay-to-Public-Key-Hash / P2PKH and modern Taproot equivalents)
- Experiment with signing and verifying transactions
- Appreciate both the power and the limitations of Bitcoin’s scripting model
- Connect theoretical signature schemes to real-world usage

This helps bridge the gap between “I understand digital signatures” and “I understand how Bitcoin actually works.”

## Learning Objectives
By using this demo, a student should be able to:
- Explain the basic concept of Bitcoin Script as a stack-based language
- Understand how a typical P2PKH (Pay-to-Public-Key-Hash) script works
- See the process of signing a transaction and how the signature is checked
- Recognize why certain script patterns became standard
- Understand the evolution toward Taproot and more advanced spending conditions

## Required Sections & Flow

### 1. What is Bitcoin Script?
- Simple, clear explanation of Bitcoin’s stack-based scripting language.
- Contrast with more expressive smart contract platforms (e.g., Ethereum).
- Show why Bitcoin Script is intentionally limited and secure-by-design.

### 2. Common Script Patterns
- Focus on the most important and educational patterns:
  - Pay-to-Public-Key (P2PK)
  - Pay-to-Public-Key-Hash (P2PKH) — historically very common
  - Modern Taproot / P2TR basics (high-level)
- Visual or clear breakdown of what each script does.

### 3. Interactive Transaction Signing & Verification (Core Feature)
- User can generate or input a key pair.
- Create a simple transaction output locked with a script.
- Sign the transaction with the corresponding private key.
- Show how the script is executed during verification (stack operations).
- Allow tampering (wrong signature, wrong public key) and show why verification fails.

### 4. Script Execution Visualization
- Step-by-step view of how the script is evaluated on the stack.
- Highlight key opcodes (OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, etc.).
- Make the execution flow understandable even for students who have never seen stack languages before.

### 5. Security Properties & Limitations
- Why Bitcoin Script is designed to be simple and predictable.
- Common pitfalls and historical bugs in Bitcoin Script.
- How Taproot improves privacy and efficiency for common cases.

### 6. Real-World Context
- Show how these scripts appear in real Bitcoin transactions.
- Brief mention of more advanced use cases (multisig, timelocks, Lightning Network HTLCs) without going too deep.

## Technical Preferences
- Browser-native (HTML + TypeScript/JavaScript). WASM is acceptable if it helps with realistic script execution or signature handling.
- Use real or close-to-real Bitcoin script semantics for educational accuracy.
- Focus on clarity and visualization of script execution rather than implementing a full node or wallet.
- Clean, educational aesthetic consistent with Crypto Lab demos.

## Relationship to Existing Work
- This would complement the existing `Bitcoin Wallet` demo by going deeper into the scripting layer.
- It connects well with signature demos (ECDSA Forge, Ed25519 Forge) by showing how signatures are actually used on-chain.

## Output Requested
Please provide:
1. A recommended final display title for the demo page
2. High-level architecture and component breakdown
3. Key interactive elements (script building, signing, execution visualization)
4. Suggested visualization approach for stack execution
5. How much realism (real Bitcoin script rules) vs educational simplification is appropriate
6. Any important pedagogical notes

Start with the proposed structure, then we can iterate on implementation details.
