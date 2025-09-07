/**
 * Tests para la librería criptográfica
 */

const cryptoLib = require('../src/index');

describe('Librería Criptográfica', () => {

    // ==================== TESTS DE HASH ====================

    describe('Funciones de Hash', () => {
        const testText = 'Hola mundo criptográfico';

        test('SHA-256 debe generar un hash de 64 caracteres', () => {
            const hash = cryptoLib.sha256(testText);
            expect(hash).toHaveLength(64);
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });

        test('MD5 debe generar un hash de 32 caracteres', () => {
            const hash = cryptoLib.md5(testText);
            expect(hash).toHaveLength(32);
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });

        test('SHA-1 debe generar un hash de 40 caracteres', () => {
            const hash = cryptoLib.sha1(testText);
            expect(hash).toHaveLength(40);
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });

        test('Keccak-256 debe generar un hash de 64 caracteres', () => {
            const hash = cryptoLib.keccak256(testText);
            expect(hash).toHaveLength(64);
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });

        test('Los hashes deben ser determinísticos', () => {
            const hash1 = cryptoLib.sha256(testText);
            const hash2 = cryptoLib.sha256(testText);
            expect(hash1).toBe(hash2);
        });

        test('Diferentes textos deben generar hashes diferentes', () => {
            const hash1 = cryptoLib.sha256('texto1');
            const hash2 = cryptoLib.sha256('texto2');
            expect(hash1).not.toBe(hash2);
        });

        test('Hash de archivo debe funcionar', async () => {
            const fs = require('fs');
            const testFileContent = 'Contenido de prueba para hash de archivo';
            const testFilePath = 'test-hash-file.txt';

            // Crear archivo de prueba
            fs.writeFileSync(testFilePath, testFileContent);

            try {
                const hash = await cryptoLib.hashFile(testFilePath, 'sha256');
                expect(hash).toHaveLength(64);
                expect(hash).toMatch(/^[a-f0-9]+$/);

                // Verificar que el hash es consistente
                const hash2 = await cryptoLib.hashFile(testFilePath, 'sha256');
                expect(hash).toBe(hash2);
            } finally {
                // Limpiar archivo de prueba
                if (fs.existsSync(testFilePath)) {
                    fs.unlinkSync(testFilePath);
                }
            }
        });
    });

    // ==================== TESTS DE CIFRADO AES ====================

    describe('Cifrado AES', () => {
        const testText = 'Mensaje secreto para cifrar';
        const password = 'miPasswordSecreta123';

        test('Cifrado y descifrado AES básico debe funcionar', () => {
            const encrypted = cryptoLib.encryptAES(testText, password);
            const decrypted = cryptoLib.decryptAES(encrypted.encrypted, password, encrypted.iv);

            expect(decrypted).toBe(testText);
            expect(encrypted.iv).toBeDefined();
        });

        test('Cifrado y descifrado AES avanzado debe funcionar', () => {
            const encrypted = cryptoLib.encryptAESAdvanced(testText, password);
            const decrypted = cryptoLib.decryptAESAdvanced(encrypted, password);

            expect(decrypted).toBe(testText);
            expect(typeof encrypted).toBe('string');
        });

        test('Texto cifrado debe ser diferente al original', () => {
            const encrypted = cryptoLib.encryptAESAdvanced(testText, password);
            expect(encrypted).not.toBe(testText);
        });

        test('Contraseña incorrecta debe fallar al descifrar', () => {
            const encrypted = cryptoLib.encryptAESAdvanced(testText, password);
            const wrongPassword = 'passwordIncorrecta';

            expect(() => {
                cryptoLib.decryptAESAdvanced(encrypted, wrongPassword);
            }).toThrow();
        });

        test('Cifrado y descifrado de archivo debe funcionar', async () => {
            const fs = require('fs');
            const testFileContent = 'Contenido secreto del archivo de prueba';
            const testFilePath = 'test-encrypt-file.txt';
            const encryptedFilePath = 'test-encrypt-file.enc';
            const decryptedFilePath = 'test-encrypt-file-decrypted.txt';
            const filePassword = 'password123';

            // Crear archivo de prueba
            fs.writeFileSync(testFilePath, testFileContent);

            try {
                // Cifrar archivo
                const encryptResult = await cryptoLib.encryptFile(testFilePath, encryptedFilePath, filePassword);
                expect(encryptResult.success).toBe(true);
                expect(encryptResult.iv).toBeDefined();

                // Verificar que el archivo cifrado existe y es diferente al original
                expect(fs.existsSync(encryptedFilePath)).toBe(true);
                const encryptedContent = fs.readFileSync(encryptedFilePath);
                expect(encryptedContent.toString()).not.toBe(testFileContent);

                // Descifrar archivo
                const decryptResult = await cryptoLib.decryptFile(encryptedFilePath, decryptedFilePath, filePassword);
                expect(decryptResult.success).toBe(true);

                // Verificar que el contenido descifrado es igual al original
                expect(fs.existsSync(decryptedFilePath)).toBe(true);
                const decryptedContent = fs.readFileSync(decryptedFilePath, 'utf8');
                expect(decryptedContent).toBe(testFileContent);
            } finally {
                // Limpiar archivos de prueba
                [testFilePath, encryptedFilePath, decryptedFilePath].forEach(file => {
                    if (fs.existsSync(file)) {
                        fs.unlinkSync(file);
                    }
                });
            }
        });
    });

    // ==================== TESTS DE CIFRADO RSA ====================

    describe('Cifrado RSA', () => {
        const testText = 'Mensaje para cifrado RSA';

        test('Generación de par de claves RSA debe funcionar', () => {
            const keyPair = cryptoLib.generateRSAKeyPair();

            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.privateKey).toBeDefined();
            expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
            expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
        });

        test('Cifrado y descifrado RSA debe funcionar', () => {
            const keyPair = cryptoLib.generateRSAKeyPair();
            const encrypted = cryptoLib.encryptRSA(testText, keyPair.publicKey);
            const decrypted = cryptoLib.decryptRSA(encrypted, keyPair.privateKey);

            expect(decrypted).toBe(testText);
            expect(encrypted).not.toBe(testText);
        });

        test('Texto cifrado debe ser diferente al original', () => {
            const keyPair = cryptoLib.generateRSAKeyPair();
            const encrypted = cryptoLib.encryptRSA(testText, keyPair.publicKey);

            expect(encrypted).not.toBe(testText);
        });
    });

    // ==================== TESTS DE CURVAS ELÍPTICAS ====================

    describe('Curvas Elípticas', () => {
        const testMessage = 'Mensaje para firmar con curvas elípticas';

        test('Generación de par de claves secp256k1 debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();

            expect(keyPair.privateKey).toBeDefined();
            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.privateKey).toHaveLength(64);
            // La clave pública puede ser de 66 o 130 caracteres dependiendo del formato
            expect(keyPair.publicKey.length).toBeGreaterThan(60);
            expect(keyPair.compressed).toBe(true);
        });

        test('Firma secp256k1 debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const signature = cryptoLib.signSecp256k1(testMessage, keyPair.privateKey);

            expect(signature.signature).toBeDefined();
            expect(signature.recoveryId).toBeDefined();
            expect(signature.messageHash).toBeDefined();
            expect(signature.signature.length).toBeGreaterThan(60);
        });

        test('Generación de par de claves secp256r1 debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256r1KeyPair();

            expect(keyPair.privateKey).toBeDefined();
            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.privateKey).toHaveLength(64);
            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.compressed).toBe(true);
        });

        test('Firma secp256r1 debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256r1KeyPair();
            const signature = cryptoLib.signSecp256r1(testMessage, keyPair.privateKey);

            expect(signature.signature).toBeDefined();
            expect(signature.r).toBeDefined();
            expect(signature.s).toBeDefined();
            expect(signature.messageHash).toBeDefined();
        });

        test('Firma incorrecta debe fallar la verificación', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const signature = cryptoLib.signSecp256k1(testMessage, keyPair.privateKey);

            // Usar un mensaje diferente para la verificación
            const verified = cryptoLib.verifySecp256k1('mensaje diferente', signature.signature, keyPair.publicKey);
            expect(verified).toBe(false);
        });
    });

    // ==================== TESTS DE ETHEREUM ====================

    describe('Funciones de Ethereum', () => {
        const testMessage = 'Hola desde Ethereum!';

        test('Generación de dirección Ethereum debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const address = cryptoLib.getEthereumAddress(keyPair.publicKey);

            expect(address).toBeDefined();
            expect(address).toMatch(/^0x[a-fA-F0-9]{40}$/);
        });

        test('Firma de mensaje Ethereum debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const signature = cryptoLib.signEthereumMessage(testMessage, keyPair.privateKey);

            expect(signature.signature).toBeDefined();
            expect(signature.address).toBeDefined();
            expect(signature.message).toBeDefined();
            expect(signature.recoveryId).toBeDefined();
            expect(signature.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
        });

        test('Firma de mensaje Ethereum debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const signature = cryptoLib.signEthereumMessage(testMessage, keyPair.privateKey);

            expect(signature.signature).toBeDefined();
            expect(signature.address).toBeDefined();
            expect(signature.message).toBeDefined();
            expect(signature.recoveryId).toBeDefined();
            expect(signature.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
        });

        test('Generación de dirección Ethereum debe funcionar', () => {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const address = cryptoLib.getEthereumAddress(keyPair.publicKey);

            expect(address).toBeDefined();
            expect(address).toMatch(/^0x[a-fA-F0-9]{40}$/);
        });
    });

    // ==================== TESTS DE CODIFICACIÓN ====================

    describe('Funciones de Codificación', () => {
        const testText = 'Texto para codificar y decodificar';

        test('Codificación y decodificación Base64 debe funcionar', () => {
            const encoded = cryptoLib.encodeBase64(testText);
            const decoded = cryptoLib.decodeBase64(encoded);

            expect(decoded).toBe(testText);
            expect(encoded).not.toBe(testText);
        });

        test('Codificación y decodificación Hex debe funcionar', () => {
            const encoded = cryptoLib.encodeHex(testText);
            const decoded = cryptoLib.decodeHex(encoded);

            expect(decoded).toBe(testText);
            expect(encoded).not.toBe(testText);
        });

        test('Base64 debe generar solo caracteres válidos', () => {
            const encoded = cryptoLib.encodeBase64(testText);
            expect(encoded).toMatch(/^[A-Za-z0-9+/=]+$/);
        });

        test('Hex debe generar solo caracteres hexadecimales', () => {
            const encoded = cryptoLib.encodeHex(testText);
            expect(encoded).toMatch(/^[a-f0-9]+$/);
        });
    });

    // ==================== TESTS DE UTILIDADES ====================

    describe('Funciones de Utilidad', () => {
        test('Generación de cadena aleatoria debe funcionar', () => {
            const random1 = cryptoLib.generateRandomString(16);
            const random2 = cryptoLib.generateRandomString(16);

            expect(random1).toHaveLength(32); // 16 bytes = 32 caracteres hex
            expect(random2).toHaveLength(32);
            expect(random1).not.toBe(random2);
            expect(random1).toMatch(/^[a-f0-9]+$/);
        });

        test('Generación de salt debe funcionar', () => {
            const salt1 = cryptoLib.generateSalt();
            const salt2 = cryptoLib.generateSalt();

            expect(salt1).toHaveLength(32); // 16 bytes = 32 caracteres hex
            expect(salt2).toHaveLength(32);
            expect(salt1).not.toBe(salt2);
        });

        test('Hash de contraseña debe funcionar', () => {
            const password = 'miContraseña123';
            const result = cryptoLib.hashPassword(password);

            expect(result.hash).toBeDefined();
            expect(result.salt).toBeDefined();
            expect(result.hash).toHaveLength(128); // 64 bytes = 128 caracteres hex
            expect(result.salt).toHaveLength(32);
        });

        test('Verificación de contraseña debe funcionar', () => {
            const password = 'miContraseña123';
            const { hash, salt } = cryptoLib.hashPassword(password);

            expect(cryptoLib.verifyPassword(password, hash, salt)).toBe(true);
            expect(cryptoLib.verifyPassword('contraseñaIncorrecta', hash, salt)).toBe(false);
        });

        test('Hash de contraseña con salt personalizado debe funcionar', () => {
            const password = 'miContraseña123';
            const customSalt = cryptoLib.generateSalt();
            const result = cryptoLib.hashPassword(password, customSalt);

            expect(result.salt).toBe(customSalt);
            expect(cryptoLib.verifyPassword(password, result.hash, customSalt)).toBe(true);
        });
    });

    // ==================== TESTS DE INTEGRACIÓN ====================

    describe('Tests de Integración', () => {
        test('Flujo completo de cifrado y hash debe funcionar', () => {
            const originalText = 'Mensaje muy secreto';
            const password = 'password123';

            // 1. Generar hash del texto original
            const originalHash = cryptoLib.sha256(originalText);

            // 2. Cifrar el texto
            const encrypted = cryptoLib.encryptAESAdvanced(originalText, password);

            // 3. Descifrar el texto
            const decrypted = cryptoLib.decryptAESAdvanced(encrypted, password);

            // 4. Verificar que el texto descifrado es igual al original
            expect(decrypted).toBe(originalText);

            // 5. Verificar que el hash del texto descifrado es igual al original
            const decryptedHash = cryptoLib.sha256(decrypted);
            expect(decryptedHash).toBe(originalHash);
        });

        test('Flujo de autenticación con hash de contraseña debe funcionar', () => {
            const username = 'usuario123';
            const password = 'miPasswordSecreta';

            // 1. Registrar usuario (generar hash de contraseña)
            const { hash, salt } = cryptoLib.hashPassword(password);

            // 2. Simular login (verificar contraseña)
            const isValid = cryptoLib.verifyPassword(password, hash, salt);
            expect(isValid).toBe(true);

            // 3. Verificar que contraseña incorrecta falla
            const isInvalid = cryptoLib.verifyPassword('passwordIncorrecta', hash, salt);
            expect(isInvalid).toBe(false);
        });
    });
});
