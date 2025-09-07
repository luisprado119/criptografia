/**
 * Librería Criptográfica en JavaScript
 * Proporciona funciones para hash, cifrado simétrico, asimétrico y codificación
 */

const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const keccak = require('keccak');
const secp256k1 = require('secp256k1');
const EC = require('elliptic').ec;
const fs = require('fs');
const path = require('path');

// ==================== FUNCIONES DE HASH ====================

/**
 * Genera un hash SHA-256 de un texto
 * @param {string} text - Texto a hashear
 * @returns {string} Hash SHA-256 en formato hexadecimal
 */
function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Genera un hash MD5 de un texto
 * @param {string} text - Texto a hashear
 * @returns {string} Hash MD5 en formato hexadecimal
 */
function md5(text) {
    return crypto.createHash('md5').update(text).digest('hex');
}

/**
 * Genera un hash SHA-1 de un texto
 * @param {string} text - Texto a hashear
 * @returns {string} Hash SHA-1 en formato hexadecimal
 */
function sha1(text) {
    return crypto.createHash('sha1').update(text).digest('hex');
}

/**
 * Genera un hash Keccak-256 de un texto (usado en Ethereum)
 * @param {string} text - Texto a hashear
 * @returns {string} Hash Keccak-256 en formato hexadecimal
 */
function keccak256(text) {
    return keccak('keccak256').update(text).digest('hex');
}

/**
 * Genera un hash de un archivo
 * @param {string} filePath - Ruta del archivo
 * @param {string} algorithm - Algoritmo de hash (sha256, md5, sha1, keccak256)
 * @returns {Promise<string>} Hash del archivo
 */
async function hashFile(filePath, algorithm = 'sha256') {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(filePath)) {
            reject(new Error(`Archivo no encontrado: ${filePath}`));
            return;
        }

        const hash = crypto.createHash(algorithm);
        const stream = fs.createReadStream(filePath);

        stream.on('data', (data) => hash.update(data));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', (error) => reject(error));
    });
}

// ==================== CIFRADO SIMÉTRICO (AES) ====================

/**
 * Cifra un texto usando AES-256-CBC
 * @param {string} text - Texto a cifrar
 * @param {string} password - Contraseña para el cifrado
 * @returns {Object} Objeto con el texto cifrado y el IV
 */
function encryptAES(text, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, 'salt', 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
        encrypted: encrypted,
        iv: iv.toString('hex')
    };
}

/**
 * Descifra un texto usando AES-256-CBC
 * @param {string} encryptedText - Texto cifrado
 * @param {string} password - Contraseña para el descifrado
 * @param {string} iv - Vector de inicialización en hex
 * @returns {string} Texto descifrado
 */
function decryptAES(encryptedText, password, iv) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Cifra un texto usando AES con CryptoJS (más robusto)
 * @param {string} text - Texto a cifrar
 * @param {string} password - Contraseña para el cifrado
 * @returns {string} Texto cifrado en formato Base64
 */
function encryptAESAdvanced(text, password) {
    return CryptoJS.AES.encrypt(text, password).toString();
}

/**
 * Descifra un texto usando AES con CryptoJS
 * @param {string} encryptedText - Texto cifrado en Base64
 * @param {string} password - Contraseña para el descifrado
 * @returns {string} Texto descifrado
 */
function decryptAESAdvanced(encryptedText, password) {
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedText, password);
        const decrypted = bytes.toString(CryptoJS.enc.Utf8);

        if (!decrypted) {
            throw new Error('Contraseña incorrecta o datos corruptos');
        }

        return decrypted;
    } catch (error) {
        throw new Error('Error al descifrar: ' + error.message);
    }
}

/**
 * Cifra un archivo usando AES-256-CBC
 * @param {string} inputFilePath - Ruta del archivo a cifrar
 * @param {string} outputFilePath - Ruta del archivo cifrado
 * @param {string} password - Contraseña para el cifrado
 * @returns {Promise<Object>} Objeto con información del cifrado
 */
async function encryptFile(inputFilePath, outputFilePath, password) {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(inputFilePath)) {
            reject(new Error(`Archivo no encontrado: ${inputFilePath}`));
            return;
        }

        try {
            const iv = crypto.randomBytes(16);
            const key = crypto.scryptSync(password, 'salt', 32);
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

            const inputStream = fs.createReadStream(inputFilePath);
            const outputStream = fs.createWriteStream(outputFilePath);

            // Escribir IV al inicio del archivo
            outputStream.write(iv);

            inputStream.pipe(cipher).pipe(outputStream);

            outputStream.on('finish', () => {
                resolve({
                    success: true,
                    inputFile: inputFilePath,
                    outputFile: outputFilePath,
                    iv: iv.toString('hex')
                });
            });

            outputStream.on('error', reject);
            inputStream.on('error', reject);
        } catch (error) {
            reject(error);
        }
    });
}

/**
 * Descifra un archivo usando AES-256-CBC
 * @param {string} inputFilePath - Ruta del archivo cifrado
 * @param {string} outputFilePath - Ruta del archivo descifrado
 * @param {string} password - Contraseña para el descifrado
 * @returns {Promise<Object>} Objeto con información del descifrado
 */
async function decryptFile(inputFilePath, outputFilePath, password) {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(inputFilePath)) {
            reject(new Error(`Archivo no encontrado: ${inputFilePath}`));
            return;
        }

        try {
            const key = crypto.scryptSync(password, 'salt', 32);

            // Leer el archivo completo
            const encryptedData = fs.readFileSync(inputFilePath);

            // Extraer IV (primeros 16 bytes)
            const iv = encryptedData.slice(0, 16);
            const encrypted = encryptedData.slice(16);

            // Descifrar
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            let decrypted = decipher.update(encrypted);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            // Escribir archivo descifrado
            fs.writeFileSync(outputFilePath, decrypted);

            resolve({
                success: true,
                inputFile: inputFilePath,
                outputFile: outputFilePath
            });
        } catch (error) {
            reject(new Error('Contraseña incorrecta o archivo corrupto'));
        }
    });
}

// ==================== CIFRADO ASIMÉTRICO (RSA) ====================

/**
 * Genera un par de claves RSA
 * @param {number} keySize - Tamaño de la clave en bits (por defecto 2048)
 * @returns {Object} Objeto con clave pública y privada
 */
function generateRSAKeyPair(keySize = 2048) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return { publicKey, privateKey };
}

/**
 * Cifra un texto usando RSA con clave pública
 * @param {string} text - Texto a cifrar
 * @param {string} publicKey - Clave pública en formato PEM
 * @returns {string} Texto cifrado en Base64
 */
function encryptRSA(text, publicKey) {
    const buffer = Buffer.from(text, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

/**
 * Descifra un texto usando RSA con clave privada
 * @param {string} encryptedText - Texto cifrado en Base64
 * @param {string} privateKey - Clave privada en formato PEM
 * @returns {string} Texto descifrado
 */
function decryptRSA(encryptedText, privateKey) {
    const buffer = Buffer.from(encryptedText, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf8');
}

// ==================== CURVAS ELÍPTICAS ====================

/**
 * Genera un par de claves secp256k1 (usado en Bitcoin y Ethereum)
 * @returns {Object} Objeto con clave privada y pública
 */
function generateSecp256k1KeyPair() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privateKey));

    const publicKey = secp256k1.publicKeyCreate(privateKey);

    return {
        privateKey: privateKey.toString('hex'),
        publicKey: publicKey.toString('hex'),
        compressed: true
    };
}

/**
 * Firma un mensaje usando secp256k1
 * @param {string} message - Mensaje a firmar
 * @param {string} privateKeyHex - Clave privada en hexadecimal
 * @returns {Object} Objeto con la firma
 */
function signSecp256k1(message, privateKeyHex) {
    const privateKey = Buffer.from(privateKeyHex, 'hex');
    const messageHash = keccak256(message);
    const messageBuffer = Buffer.from(messageHash, 'hex');

    const signature = secp256k1.ecdsaSign(messageBuffer, privateKey);

    return {
        signature: signature.signature.toString('hex'),
        recoveryId: signature.recid,
        messageHash: messageHash
    };
}

/**
 * Verifica una firma secp256k1
 * @param {string} message - Mensaje original
 * @param {string} signatureHex - Firma en hexadecimal
 * @param {string} publicKeyHex - Clave pública en hexadecimal
 * @returns {boolean} True si la firma es válida
 */
function verifySecp256k1(message, signatureHex, publicKeyHex) {
    try {
        const publicKey = Buffer.from(publicKeyHex, 'hex');
        const signature = Buffer.from(signatureHex, 'hex');
        const messageHash = keccak256(message);
        const messageBuffer = Buffer.from(messageHash, 'hex');

        return secp256k1.ecdsaVerify(signature, messageBuffer, publicKey);
    } catch (error) {
        return false;
    }
}

/**
 * Genera un par de claves secp256r1 (P-256)
 * @returns {Object} Objeto con clave privada y pública
 */
function generateSecp256r1KeyPair() {
    const ec = new EC('p256');
    const keyPair = ec.genKeyPair();

    return {
        privateKey: keyPair.getPrivate('hex'),
        publicKey: keyPair.getPublic('hex'),
        compressed: true
    };
}

/**
 * Firma un mensaje usando secp256r1
 * @param {string} message - Mensaje a firmar
 * @param {string} privateKeyHex - Clave privada en hexadecimal
 * @returns {Object} Objeto con la firma
 */
function signSecp256r1(message, privateKeyHex) {
    const ec = new EC('p256');
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');
    const messageHash = sha256(message);
    const signature = keyPair.sign(messageHash);

    return {
        signature: signature.toDER('hex'),
        r: signature.r.toString('hex'),
        s: signature.s.toString('hex'),
        messageHash: messageHash
    };
}

/**
 * Verifica una firma secp256r1
 * @param {string} message - Mensaje original
 * @param {string} signatureHex - Firma en hexadecimal
 * @param {string} publicKeyHex - Clave pública en hexadecimal
 * @returns {boolean} True si la firma es válida
 */
function verifySecp256r1(message, signatureHex, publicKeyHex) {
    try {
        const ec = new EC('p256');
        const keyPair = ec.keyFromPublic(publicKeyHex, 'hex');
        const messageHash = sha256(message);
        const signature = ec.signatureFromDER(signatureHex);

        return keyPair.verify(messageHash, signature);
    } catch (error) {
        return false;
    }
}

// ==================== FUNCIONES DE ETHEREUM ====================

/**
 * Genera una dirección Ethereum desde una clave pública secp256k1
 * @param {string} publicKeyHex - Clave pública en hexadecimal
 * @returns {string} Dirección Ethereum
 */
function getEthereumAddress(publicKeyHex) {
    const publicKey = Buffer.from(publicKeyHex, 'hex');
    const hash = keccak256(publicKey.slice(1).toString('hex'));
    return '0x' + hash.slice(-40);
}

/**
 * Firma un mensaje Ethereum (con prefijo)
 * @param {string} message - Mensaje a firmar
 * @param {string} privateKeyHex - Clave privada en hexadecimal
 * @returns {Object} Objeto con la firma y dirección
 */
function signEthereumMessage(message, privateKeyHex) {
    const ethereumMessage = `\x19Ethereum Signed Message:\n${message.length}${message}`;
    const signature = signSecp256k1(ethereumMessage, privateKeyHex);
    const publicKey = secp256k1.publicKeyCreate(Buffer.from(privateKeyHex, 'hex'));
    const address = getEthereumAddress(publicKey.toString('hex'));

    return {
        ...signature,
        address: address,
        message: ethereumMessage
    };
}

/**
 * Verifica una firma de mensaje Ethereum
 * @param {string} message - Mensaje original
 * @param {string} signatureHex - Firma en hexadecimal
 * @param {string} address - Dirección Ethereum
 * @returns {boolean} True si la firma es válida
 */
function verifyEthereumMessage(message, signatureHex, address) {
    const ethereumMessage = `\x19Ethereum Signed Message:\n${message.length}${message}`;
    const messageHash = keccak256(ethereumMessage);

    try {
        const signature = Buffer.from(signatureHex, 'hex');
        const recoveryId = signature[64];
        const r = signature.slice(0, 32);
        const s = signature.slice(32, 64);

        const publicKey = secp256k1.ecdsaRecover(Buffer.concat([r, s]), recoveryId, Buffer.from(messageHash, 'hex'));
        const recoveredAddress = getEthereumAddress(publicKey.toString('hex'));

        return recoveredAddress.toLowerCase() === address.toLowerCase();
    } catch (error) {
        return false;
    }
}

// ==================== FUNCIONES DE CODIFICACIÓN ====================

/**
 * Codifica un texto a Base64
 * @param {string} text - Texto a codificar
 * @returns {string} Texto codificado en Base64
 */
function encodeBase64(text) {
    return Buffer.from(text, 'utf8').toString('base64');
}

/**
 * Decodifica un texto desde Base64
 * @param {string} base64Text - Texto en Base64
 * @returns {string} Texto decodificado
 */
function decodeBase64(base64Text) {
    return Buffer.from(base64Text, 'base64').toString('utf8');
}

/**
 * Codifica un texto a hexadecimal
 * @param {string} text - Texto a codificar
 * @returns {string} Texto codificado en hexadecimal
 */
function encodeHex(text) {
    return Buffer.from(text, 'utf8').toString('hex');
}

/**
 * Decodifica un texto desde hexadecimal
 * @param {string} hexText - Texto en hexadecimal
 * @returns {string} Texto decodificado
 */
function decodeHex(hexText) {
    return Buffer.from(hexText, 'hex').toString('utf8');
}

// ==================== FUNCIONES DE UTILIDAD ====================

/**
 * Genera una cadena aleatoria segura
 * @param {number} length - Longitud de la cadena
 * @returns {string} Cadena aleatoria
 */
function generateRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Genera un salt para hash de contraseñas
 * @param {number} length - Longitud del salt
 * @returns {string} Salt aleatorio
 */
function generateSalt(length = 16) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Genera un hash de contraseña con salt
 * @param {string} password - Contraseña
 * @param {string} salt - Salt (opcional, se genera uno si no se proporciona)
 * @returns {Object} Objeto con el hash y el salt
 */
function hashPassword(password, salt = null) {
    if (!salt) {
        salt = generateSalt();
    }
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return { hash, salt };
}

/**
 * Verifica una contraseña contra su hash
 * @param {string} password - Contraseña a verificar
 * @param {string} hash - Hash almacenado
 * @param {string} salt - Salt usado
 * @returns {boolean} True si la contraseña es correcta
 */
function verifyPassword(password, hash, salt) {
    const newHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return newHash === hash;
}

// ==================== EXPORTACIONES ====================

module.exports = {
    // Hash functions
    sha256,
    md5,
    sha1,
    keccak256,
    hashFile,

    // AES encryption
    encryptAES,
    decryptAES,
    encryptAESAdvanced,
    decryptAESAdvanced,
    encryptFile,
    decryptFile,

    // RSA encryption
    generateRSAKeyPair,
    encryptRSA,
    decryptRSA,

    // Elliptic curves
    generateSecp256k1KeyPair,
    signSecp256k1,
    verifySecp256k1,
    generateSecp256r1KeyPair,
    signSecp256r1,
    verifySecp256r1,

    // Ethereum functions
    getEthereumAddress,
    signEthereumMessage,
    verifyEthereumMessage,

    // Encoding functions
    encodeBase64,
    decodeBase64,
    encodeHex,
    decodeHex,

    // Utility functions
    generateRandomString,
    generateSalt,
    hashPassword,
    verifyPassword
};
