export class HashEncrypter {

    async getKeyFromPassword(password: string, keyLength: number = 256): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(password);
        const key = await crypto.subtle.digest({ name: 'SHA-256' }, keyData);

        // If keyLength is 128, we truncate the SHA-256 hash to 16 bytes
        const keyMaterial = keyLength === 128 ? key.slice(0, 16) : key;

        return crypto.subtle.importKey(
            "raw",
            keyMaterial,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async encrypt(plainText: string, secret: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(plainText);
        const key = await this.getKeyFromPassword(secret, 256); // You can change 256 to 128 if you prefer a shorter key
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );

        const p1 = Array.from(new Uint8Array(encrypted)).map(char => String.fromCharCode(char)).join('');
        const p2 = Array.from(iv).map(char => String.fromCharCode(char)).join('');

        return `${btoa(p1)}:${btoa(p2)}:::`;
    }

    async decrypt(encryptedText: string, secret: string): Promise<string> {
        const chunks = encryptedText.split(':::');
        // For each chunk with length > 0, decrypt it and add to the result
        const result = await Promise.all(chunks.filter(chunk => chunk.length > 0).map(chunk => this.decryptSingle(chunk, secret)));
        return result.join('');

    };

    async decryptSingle(encryptedText: string, secret: string): Promise<string> {
        const decoder = new TextDecoder();
        const [encryptedBase64, ivBase64] = encryptedText.split(':');
        const iv = new Uint8Array(atob(ivBase64).split('').map(char => char.charCodeAt(0)));
        const data = new Uint8Array(atob(encryptedBase64).split('').map(char => char.charCodeAt(0)));
        const key = await this.getKeyFromPassword(secret, 256); // Match the key length used in encryption

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );
        return decoder.decode(decrypted);
    }
}
