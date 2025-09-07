/**
 * Archivo principal para demostrar la librería criptográfica expandida
 * Incluye ejemplos de Ethereum, curvas elípticas y cifrado de archivos
 */

const cryptoLib = require('./src/index');
const fs = require('fs');

console.log('🔐 DEMOSTRACIÓN DE LA LIBRERÍA CRIPTOGRÁFICA EXPANDIDA 🔐\n');

// ==================== DEMOSTRACIÓN DE HASH ====================

console.log('📊 FUNCIONES DE HASH:');
console.log('='.repeat(50));

const textoOriginal = 'Hola mundo criptográfico desde JavaScript!';
console.log(`Texto original: "${textoOriginal}"\n`);

// SHA-256
const hashSHA256 = cryptoLib.sha256(textoOriginal);
console.log(`SHA-256: ${hashSHA256}`);

// MD5
const hashMD5 = cryptoLib.md5(textoOriginal);
console.log(`MD5:     ${hashMD5}`);

// SHA-1
const hashSHA1 = cryptoLib.sha1(textoOriginal);
console.log(`SHA-1:   ${hashSHA1}`);

// Keccak-256 (Ethereum)
const hashKeccak256 = cryptoLib.keccak256(textoOriginal);
console.log(`Keccak-256: ${hashKeccak256}\n`);

// ==================== DEMOSTRACIÓN DE HASH DE ARCHIVOS ====================

console.log('📁 HASH DE ARCHIVOS:');
console.log('='.repeat(50));

// Crear un archivo de prueba
const testFileContent = 'Este es un archivo de prueba para demostrar el hash de archivos.\nContiene múltiples líneas de texto.';
const testFilePath = 'test-file.txt';
fs.writeFileSync(testFilePath, testFileContent);

console.log(`Archivo creado: ${testFilePath}`);
console.log(`Contenido: "${testFileContent}"\n`);

// Hash del archivo
cryptoLib.hashFile(testFilePath, 'sha256').then(hash => {
    console.log(`Hash SHA-256 del archivo: ${hash}`);

    // Hash con Keccak-256
    return cryptoLib.hashFile(testFilePath, 'keccak256');
}).then(hash => {
    console.log(`Hash Keccak-256 del archivo: ${hash}\n`);
}).catch(error => {
    console.error('Error al hashear archivo:', error.message);
});

// ==================== DEMOSTRACIÓN DE CIFRADO DE ARCHIVOS ====================

console.log('🔒 CIFRADO DE ARCHIVOS:');
console.log('='.repeat(50));

const filePassword = 'miPasswordParaArchivos123';
const encryptedFilePath = 'test-file-encrypted.enc';
const decryptedFilePath = 'test-file-decrypted.txt';

console.log(`Archivo original: ${testFilePath}`);
console.log(`Contraseña: "${filePassword}"\n`);

// Cifrar archivo
cryptoLib.encryptFile(testFilePath, encryptedFilePath, filePassword).then(result => {
    console.log(`✅ Archivo cifrado exitosamente:`);
    console.log(`   - Archivo cifrado: ${result.outputFile}`);
    console.log(`   - IV: ${result.iv}\n`);

    // Descifrar archivo
    return cryptoLib.decryptFile(encryptedFilePath, decryptedFilePath, filePassword);
}).then(result => {
    console.log(`✅ Archivo descifrado exitosamente:`);
    console.log(`   - Archivo descifrado: ${result.outputFile}`);

    // Verificar contenido
    const decryptedContent = fs.readFileSync(decryptedFilePath, 'utf8');
    console.log(`   - Contenido descifrado: "${decryptedContent}"`);
    console.log(`   - Contenido original: "${testFileContent}"`);
    console.log(`   - ¿Coinciden?: ${decryptedContent === testFileContent ? '✅ Sí' : '❌ No'}\n`);
}).catch(error => {
    console.error('Error en cifrado de archivos:', error.message);
});

// ==================== DEMOSTRACIÓN DE CURVAS ELÍPTICAS ====================

console.log('🔑 CURVAS ELÍPTICAS:');
console.log('='.repeat(50));

// secp256k1 (Bitcoin/Ethereum)
console.log('--- secp256k1 (Bitcoin/Ethereum) ---');
const secp256k1KeyPair = cryptoLib.generateSecp256k1KeyPair();
console.log(`Clave privada: ${secp256k1KeyPair.privateKey}`);
console.log(`Clave pública: ${secp256k1KeyPair.publicKey}`);

const messageToSign = 'Mensaje para firmar con secp256k1';
const secp256k1Signature = cryptoLib.signSecp256k1(messageToSign, secp256k1KeyPair.privateKey);
console.log(`Mensaje: "${messageToSign}"`);
console.log(`Firma: ${secp256k1Signature.signature}`);
console.log(`Recovery ID: ${secp256k1Signature.recoveryId}`);

const secp256k1Verified = cryptoLib.verifySecp256k1(messageToSign, secp256k1Signature.signature, secp256k1KeyPair.publicKey);
console.log(`Verificación: ${secp256k1Verified ? '✅ Válida' : '❌ Inválida'}\n`);

// secp256r1 (P-256)
console.log('--- secp256r1 (P-256) ---');
const secp256r1KeyPair = cryptoLib.generateSecp256r1KeyPair();
console.log(`Clave privada: ${secp256r1KeyPair.privateKey}`);
console.log(`Clave pública: ${secp256r1KeyPair.publicKey}`);

const messageToSignR1 = 'Mensaje para firmar con secp256r1';
const secp256r1Signature = cryptoLib.signSecp256r1(messageToSignR1, secp256r1KeyPair.privateKey);
console.log(`Mensaje: "${messageToSignR1}"`);
console.log(`Firma: ${secp256r1Signature.signature}`);
console.log(`R: ${secp256r1Signature.r}`);
console.log(`S: ${secp256r1Signature.s}`);

const secp256r1Verified = cryptoLib.verifySecp256r1(messageToSignR1, secp256r1Signature.signature, secp256r1KeyPair.publicKey);
console.log(`Verificación: ${secp256r1Verified ? '✅ Válida' : '❌ Inválida'}\n`);

// ==================== DEMOSTRACIÓN DE ETHEREUM ====================

console.log('🚀 FUNCIONES DE ETHEREUM:');
console.log('='.repeat(50));

// Generar wallet Ethereum
console.log('--- Generación de Wallet Ethereum ---');
const ethereumKeyPair = cryptoLib.generateSecp256k1KeyPair();
const ethereumAddress = cryptoLib.getEthereumAddress(ethereumKeyPair.publicKey);

console.log(`Clave privada: ${ethereumKeyPair.privateKey}`);
console.log(`Clave pública: ${ethereumKeyPair.publicKey}`);
console.log(`Dirección Ethereum: ${ethereumAddress}\n`);

// Firmar mensaje Ethereum
console.log('--- Firma de Mensaje Ethereum ---');
const ethereumMessage = 'Hola desde mi wallet Ethereum!';
const ethereumSignature = cryptoLib.signEthereumMessage(ethereumMessage, ethereumKeyPair.privateKey);

console.log(`Mensaje: "${ethereumMessage}"`);
console.log(`Mensaje Ethereum: "${ethereumSignature.message}"`);
console.log(`Firma: ${ethereumSignature.signature}`);
console.log(`Dirección: ${ethereumSignature.address}`);
console.log(`Recovery ID: ${ethereumSignature.recoveryId}\n`);

// Verificar mensaje Ethereum
console.log('--- Verificación de Mensaje Ethereum ---');
const ethereumVerified = cryptoLib.verifyEthereumMessage(ethereumMessage, ethereumSignature.signature, ethereumAddress);
console.log(`Verificación: ${ethereumVerified ? '✅ Válida' : '❌ Inválida'}`);

// Simular transacción Ethereum
console.log('\n--- Simulación de Transacción Ethereum ---');
const transaction = {
    from: ethereumAddress,
    to: '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
    value: '1000000000000000000', // 1 ETH en wei
    gas: '21000',
    gasPrice: '20000000000', // 20 gwei
    nonce: 0
};

const transactionHash = cryptoLib.keccak256(JSON.stringify(transaction));
console.log(`Transacción: ${JSON.stringify(transaction, null, 2)}`);
console.log(`Hash de transacción: ${transactionHash}`);

const transactionSignature = cryptoLib.signSecp256k1(transactionHash, ethereumKeyPair.privateKey);
console.log(`Firma de transacción: ${transactionSignature.signature}\n`);

// ==================== DEMOSTRACIÓN DE CIFRADO SIMÉTRICO ====================

console.log('🔒 CIFRADO SIMÉTRICO (AES):');
console.log('='.repeat(50));

const mensajeSecreto = 'Este es un mensaje muy secreto que necesita protección!';
const password = 'miPasswordSuperSecreta123';
console.log(`Mensaje original: "${mensajeSecreto}"`);
console.log(`Contraseña: "${password}"\n`);

// Cifrado AES básico
const aesEncrypted = cryptoLib.encryptAES(mensajeSecreto, password);
console.log(`AES Cifrado (básico): ${aesEncrypted.encrypted}`);
console.log(`IV: ${aesEncrypted.iv}`);

const aesDecrypted = cryptoLib.decryptAES(aesEncrypted.encrypted, password, aesEncrypted.iv);
console.log(`AES Descifrado: "${aesDecrypted}"\n`);

// Cifrado AES avanzado
const aesAdvancedEncrypted = cryptoLib.encryptAESAdvanced(mensajeSecreto, password);
console.log(`AES Cifrado (avanzado): ${aesAdvancedEncrypted}`);

const aesAdvancedDecrypted = cryptoLib.decryptAESAdvanced(aesAdvancedEncrypted, password);
console.log(`AES Descifrado (avanzado): "${aesAdvancedDecrypted}"\n`);

// ==================== DEMOSTRACIÓN DE CIFRADO ASIMÉTRICO ====================

console.log('🔑 CIFRADO ASIMÉTRICO (RSA):');
console.log('='.repeat(50));

const mensajeRSA = 'Mensaje para cifrado asimétrico RSA';
console.log(`Mensaje original: "${mensajeRSA}"\n`);

// Generar par de claves
console.log('Generando par de claves RSA...');
const keyPair = cryptoLib.generateRSAKeyPair(2048);
console.log('✅ Par de claves generado exitosamente\n');

// Cifrar con clave pública
const rsaEncrypted = cryptoLib.encryptRSA(mensajeRSA, keyPair.publicKey);
console.log(`RSA Cifrado: ${rsaEncrypted.substring(0, 100)}...`);

// Descifrar con clave privada
const rsaDecrypted = cryptoLib.decryptRSA(rsaEncrypted, keyPair.privateKey);
console.log(`RSA Descifrado: "${rsaDecrypted}"\n`);

// ==================== DEMOSTRACIÓN DE CODIFICACIÓN ====================

console.log('🔤 FUNCIONES DE CODIFICACIÓN:');
console.log('='.repeat(50));

const textoParaCodificar = 'Datos sensibles para codificar';
console.log(`Texto original: "${textoParaCodificar}"\n`);

// Base64
const base64Encoded = cryptoLib.encodeBase64(textoParaCodificar);
const base64Decoded = cryptoLib.decodeBase64(base64Encoded);
console.log(`Base64 codificado: ${base64Encoded}`);
console.log(`Base64 decodificado: "${base64Decoded}"\n`);

// Hexadecimal
const hexEncoded = cryptoLib.encodeHex(textoParaCodificar);
const hexDecoded = cryptoLib.decodeHex(hexEncoded);
console.log(`Hex codificado: ${hexEncoded}`);
console.log(`Hex decodificado: "${hexDecoded}"\n`);

// ==================== DEMOSTRACIÓN DE UTILIDADES ====================

console.log('🛠️  FUNCIONES DE UTILIDAD:');
console.log('='.repeat(50));

// Generar cadena aleatoria
const randomString = cryptoLib.generateRandomString(16);
console.log(`Cadena aleatoria (16 bytes): ${randomString}`);

// Generar salt
const salt = cryptoLib.generateSalt();
console.log(`Salt generado: ${salt}\n`);

// Hash de contraseña
const usuarioPassword = 'miContraseñaSuperSecreta123';
console.log(`Contraseña original: "${usuarioPassword}"`);

const passwordHash = cryptoLib.hashPassword(usuarioPassword);
console.log(`Hash de contraseña: ${passwordHash.hash}`);
console.log(`Salt usado: ${passwordHash.salt}`);

// Verificar contraseña
const verificacionCorrecta = cryptoLib.verifyPassword(usuarioPassword, passwordHash.hash, passwordHash.salt);
const verificacionIncorrecta = cryptoLib.verifyPassword('contraseñaIncorrecta', passwordHash.hash, passwordHash.salt);

console.log(`Verificación con contraseña correcta: ${verificacionCorrecta ? '✅ Correcta' : '❌ Incorrecta'}`);
console.log(`Verificación con contraseña incorrecta: ${verificacionIncorrecta ? '✅ Correcta' : '❌ Incorrecta'}\n`);

// ==================== DEMOSTRACIÓN DE FLUJO COMPLETO ====================

console.log('🔄 FLUJO COMPLETO DE SEGURIDAD:');
console.log('='.repeat(50));

const documentoSecreto = 'Documento confidencial: Planes secretos de la empresa';
const masterPassword = 'MasterPassword2024!';

console.log(`Documento original: "${documentoSecreto}"`);
console.log(`Contraseña maestra: "${masterPassword}"\n`);

// Paso 1: Generar hash del documento para integridad
const documentoHash = cryptoLib.sha256(documentoSecreto);
console.log(`1. Hash de integridad: ${documentoHash}`);

// Paso 2: Cifrar el documento
const documentoCifrado = cryptoLib.encryptAESAdvanced(documentoSecreto, masterPassword);
console.log(`2. Documento cifrado: ${documentoCifrado.substring(0, 50)}...`);

// Paso 3: Simular almacenamiento y recuperación
console.log('\n--- Simulando almacenamiento y recuperación ---');

// Paso 4: Descifrar el documento
const documentoDescifrado = cryptoLib.decryptAESAdvanced(documentoCifrado, masterPassword);
console.log(`3. Documento descifrado: "${documentoDescifrado}"`);

// Paso 5: Verificar integridad
const documentoHashVerificado = cryptoLib.sha256(documentoDescifrado);
const integridadVerificada = documentoHash === documentoHashVerificado;
console.log(`4. Hash verificado: ${documentoHashVerificado}`);
console.log(`5. Integridad verificada: ${integridadVerificada ? '✅ Documento íntegro' : '❌ Documento corrupto'}\n`);

// ==================== DEMOSTRACIÓN DE SISTEMA DE AUTENTICACIÓN ====================

console.log('👤 SISTEMA DE AUTENTICACIÓN SIMULADO:');
console.log('='.repeat(50));

// Simular registro de usuario
const nuevoUsuario = {
    username: 'admin',
    email: 'admin@empresa.com',
    password: 'admin123!'
};

console.log('--- Registro de usuario ---');
console.log(`Usuario: ${nuevoUsuario.username}`);
console.log(`Email: ${nuevoUsuario.email}`);
console.log(`Contraseña: ${nuevoUsuario.password}`);

const { hash: passwordHashRegistro, salt: passwordSalt } = cryptoLib.hashPassword(nuevoUsuario.password);
console.log(`Hash de contraseña: ${passwordHashRegistro}`);
console.log(`Salt: ${passwordSalt}\n`);

// Simular login
console.log('--- Intento de login ---');
const loginPassword = 'admin123!';
const loginExitoso = cryptoLib.verifyPassword(loginPassword, passwordHashRegistro, passwordSalt);

console.log(`Contraseña ingresada: ${loginPassword}`);
console.log(`Login exitoso: ${loginExitoso ? '✅ Acceso concedido' : '❌ Acceso denegado'}\n`);

// Simular login con contraseña incorrecta
console.log('--- Intento de login con contraseña incorrecta ---');
const loginPasswordIncorrecta = 'password123';
const loginFallido = cryptoLib.verifyPassword(loginPasswordIncorrecta, passwordHashRegistro, passwordSalt);

console.log(`Contraseña ingresada: ${loginPasswordIncorrecta}`);
console.log(`Login exitoso: ${loginFallido ? '✅ Acceso concedido' : '❌ Acceso denegado'}\n`);

// ==================== LIMPIEZA ====================

console.log('🧹 LIMPIEZA DE ARCHIVOS TEMPORALES:');
console.log('='.repeat(50));

// Eliminar archivos temporales
try {
    if (fs.existsSync(testFilePath)) {
        fs.unlinkSync(testFilePath);
        console.log(`✅ Archivo eliminado: ${testFilePath}`);
    }
    if (fs.existsSync(encryptedFilePath)) {
        fs.unlinkSync(encryptedFilePath);
        console.log(`✅ Archivo eliminado: ${encryptedFilePath}`);
    }
    if (fs.existsSync(decryptedFilePath)) {
        fs.unlinkSync(decryptedFilePath);
        console.log(`✅ Archivo eliminado: ${decryptedFilePath}`);
    }
} catch (error) {
    console.log(`⚠️  Error al eliminar archivos: ${error.message}`);
}

// ==================== RESUMEN FINAL ====================

console.log('\n📋 RESUMEN DE LA LIBRERÍA EXPANDIDA:');
console.log('='.repeat(50));
console.log('✅ Funciones de Hash: SHA-256, MD5, SHA-1, Keccak-256');
console.log('✅ Hash de Archivos: SHA-256, MD5, SHA-1, Keccak-256');
console.log('✅ Cifrado Simétrico: AES-256-CBC (texto y archivos)');
console.log('✅ Cifrado Asimétrico: RSA (generación de claves, cifrado/descifrado)');
console.log('✅ Curvas Elípticas: secp256k1 (Bitcoin/Ethereum), secp256r1 (P-256)');
console.log('✅ Funciones Ethereum: Generación de direcciones, firma de mensajes');
console.log('✅ Codificación: Base64, Hexadecimal');
console.log('✅ Utilidades: Cadenas aleatorias, Salt, Hash de contraseñas');
console.log('✅ Verificación de contraseñas con PBKDF2');
console.log('\n🎉 ¡Librería criptográfica expandida funcionando correctamente! 🎉');