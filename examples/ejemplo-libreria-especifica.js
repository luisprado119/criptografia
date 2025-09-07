/**
 * EJEMPLO: Cómo usar la librería criptográfica en un proyecto específico
 * Este ejemplo muestra cómo integrar nuestra librería en diferentes escenarios
 */

const cryptoLib = require('../src/index');
const fs = require('fs');

console.log('🔧 EJEMPLO: USO DE LIBRERÍA EN PROYECTO ESPECÍFICO 🔧\n');

// ==================== EJEMPLO 1: SISTEMA DE GESTIÓN DE DOCUMENTOS ====================

console.log('📁 SISTEMA DE GESTIÓN DE DOCUMENTOS SEGUROS');
console.log('='.repeat(60));

class GestorDocumentos {
    constructor() {
        this.documentos = new Map();
        this.usuarios = new Map();
    }

    // Registrar usuario
    registrarUsuario(username, password, email) {
        const { hash, salt } = cryptoLib.hashPassword(password);
        const usuario = {
            username,
            email,
            passwordHash: hash,
            salt,
            fechaRegistro: new Date(),
            documentos: []
        };
        
        this.usuarios.set(username, usuario);
        console.log(`✅ Usuario ${username} registrado exitosamente`);
        return usuario;
    }

    // Autenticar usuario
    autenticarUsuario(username, password) {
        const usuario = this.usuarios.get(username);
        if (!usuario) {
            throw new Error('Usuario no encontrado');
        }

        const isValid = cryptoLib.verifyPassword(password, usuario.passwordHash, usuario.salt);
        if (!isValid) {
            throw new Error('Contraseña incorrecta');
        }

        console.log(`✅ Usuario ${username} autenticado exitosamente`);
        return usuario;
    }

    // Subir documento
    async subirDocumento(username, nombreDocumento, contenido, password) {
        const usuario = this.usuarios.get(username);
        if (!usuario) {
            throw new Error('Usuario no encontrado');
        }

        // Generar hash del contenido para verificar integridad
        const hashContenido = cryptoLib.sha256(contenido);
        
        // Cifrar el documento
        const documentoCifrado = cryptoLib.encryptAESAdvanced(contenido, password);
        
        // Crear metadatos del documento
        const documento = {
            id: cryptoLib.generateRandomString(16),
            nombre: nombreDocumento,
            hashOriginal: hashContenido,
            contenidoCifrado: documentoCifrado,
            fechaSubida: new Date(),
            propietario: username,
            tamaño: contenido.length
        };

        // Guardar en la "base de datos" del usuario
        usuario.documentos.push(documento);
        this.documentos.set(documento.id, documento);

        console.log(`📄 Documento "${nombreDocumento}" subido por ${username}`);
        console.log(`   ID: ${documento.id}`);
        console.log(`   Hash: ${hashContenido}`);
        console.log(`   Tamaño: ${contenido.length} bytes`);

        return documento;
    }

    // Descargar documento
    async descargarDocumento(username, documentoId, password) {
        const documento = this.documentos.get(documentoId);
        if (!documento) {
            throw new Error('Documento no encontrado');
        }

        if (documento.propietario !== username) {
            throw new Error('No tienes permisos para acceder a este documento');
        }

        try {
            // Descifrar el documento
            const contenidoDescifrado = cryptoLib.decryptAESAdvanced(documento.contenidoCifrado, password);
            
            // Verificar integridad
            const hashVerificado = cryptoLib.sha256(contenidoDescifrado);
            const integridadVerificada = hashVerificado === documento.hashOriginal;

            if (!integridadVerificada) {
                throw new Error('El documento ha sido modificado');
            }

            console.log(`📥 Documento "${documento.nombre}" descargado por ${username}`);
            console.log(`   Integridad: ${integridadVerificada ? '✅ Verificada' : '❌ Comprometida'}`);

            return {
                nombre: documento.nombre,
                contenido: contenidoDescifrado,
                integridadVerificada,
                fechaSubida: documento.fechaSubida
            };
        } catch (error) {
            throw new Error('Contraseña incorrecta o documento corrupto');
        }
    }

    // Listar documentos del usuario
    listarDocumentos(username) {
        const usuario = this.usuarios.get(username);
        if (!usuario) {
            throw new Error('Usuario no encontrado');
        }

        console.log(`📋 Documentos de ${username}:`);
        usuario.documentos.forEach((doc, index) => {
            console.log(`   ${index + 1}. ${doc.nombre} (ID: ${doc.id})`);
            console.log(`      Fecha: ${doc.fechaSubida.toLocaleDateString()}`);
            console.log(`      Tamaño: ${doc.tamaño} bytes`);
        });

        return usuario.documentos;
    }
}

// Ejemplo de uso del sistema
async function ejemploGestorDocumentos() {
    const gestor = new GestorDocumentos();

    try {
        // Registrar usuarios
        gestor.registrarUsuario('alice', 'password123', 'alice@email.com');
        gestor.registrarUsuario('bob', 'secret456', 'bob@email.com');

        // Autenticar usuario
        gestor.autenticarUsuario('alice', 'password123');

        // Subir documentos
        await gestor.subirDocumento('alice', 'contrato.pdf', 'Contenido del contrato confidencial', 'alicePassword');
        await gestor.subirDocumento('alice', 'informe.txt', 'Informe financiero Q4 2024', 'alicePassword');

        // Listar documentos
        gestor.listarDocumentos('alice');

        // Descargar documento
        const documentos = gestor.listarDocumentos('alice');
        if (documentos.length > 0) {
            const documentoDescargado = await gestor.descargarDocumento('alice', documentos[0].id, 'alicePassword');
            console.log(`\n📄 Contenido descargado: "${documentoDescargado.contenido}"`);
        }

    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// ==================== EJEMPLO 2: SISTEMA DE PAGOS CRIPTOGRÁFICO ====================

console.log('\n💰 SISTEMA DE PAGOS CRIPTOGRÁFICO');
console.log('='.repeat(60));

class SistemaPagos {
    constructor() {
        this.wallets = new Map();
        this.transacciones = [];
    }

    // Crear wallet
    crearWallet(nombreUsuario) {
        const keyPair = cryptoLib.generateSecp256k1KeyPair();
        const address = cryptoLib.getEthereumAddress(keyPair.publicKey);
        
        const wallet = {
            nombreUsuario,
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            address,
            balance: 0,
            fechaCreacion: new Date()
        };

        this.wallets.set(address, wallet);
        console.log(`💳 Wallet creado para ${nombreUsuario}`);
        console.log(`   Dirección: ${address}`);
        console.log(`   Balance inicial: ${wallet.balance} ETH`);

        return wallet;
    }

    // Crear transacción
    crearTransaccion(fromAddress, toAddress, amount, gasPrice = '20000000000') {
        const fromWallet = this.wallets.get(fromAddress);
        if (!fromWallet) {
            throw new Error('Wallet origen no encontrado');
        }

        if (fromWallet.balance < amount) {
            throw new Error('Balance insuficiente');
        }

        const transaccion = {
            from: fromAddress,
            to: toAddress,
            value: amount.toString(),
            gas: '21000',
            gasPrice: gasPrice,
            nonce: this.transacciones.length,
            timestamp: new Date()
        };

        // Firmar transacción
        const transaccionString = JSON.stringify(transaccion);
        const hashTransaccion = cryptoLib.keccak256(transaccionString);
        const signature = cryptoLib.signSecp256k1(hashTransaccion, fromWallet.privateKey);

        const transaccionFirmada = {
            ...transaccion,
            hash: hashTransaccion,
            signature: signature.signature,
            recoveryId: signature.recoveryId
        };

        this.transacciones.push(transaccionFirmada);

        console.log(`💸 Transacción creada:`);
        console.log(`   De: ${fromAddress}`);
        console.log(`   Para: ${toAddress}`);
        console.log(`   Cantidad: ${amount} ETH`);
        console.log(`   Hash: ${hashTransaccion}`);

        return transaccionFirmada;
    }

    // Procesar transacción
    procesarTransaccion(transaccionId) {
        const transaccion = this.transacciones[transaccionId];
        if (!transaccion) {
            throw new Error('Transacción no encontrada');
        }

        const fromWallet = this.wallets.get(transaccion.from);
        const toWallet = this.wallets.get(transaccion.to);

        if (!fromWallet || !toWallet) {
            throw new Error('Wallet no encontrado');
        }

        // Verificar firma
        const transaccionString = JSON.stringify({
            from: transaccion.from,
            to: transaccion.to,
            value: transaccion.value,
            gas: transaccion.gas,
            gasPrice: transaccion.gasPrice,
            nonce: transaccion.nonce
        });

        const hashVerificado = cryptoLib.keccak256(transaccionString);
        const firmaValida = cryptoLib.verifySecp256k1(hashVerificado, transaccion.signature, fromWallet.publicKey);

        if (!firmaValida) {
            throw new Error('Firma de transacción inválida');
        }

        // Ejecutar transacción
        const amount = parseFloat(transaccion.value);
        fromWallet.balance -= amount;
        toWallet.balance += amount;

        console.log(`✅ Transacción procesada exitosamente`);
        console.log(`   Hash: ${transaccion.hash}`);
        console.log(`   Balance ${fromWallet.nombreUsuario}: ${fromWallet.balance} ETH`);
        console.log(`   Balance ${toWallet.nombreUsuario}: ${toWallet.balance} ETH`);

        return {
            exito: true,
            hash: transaccion.hash,
            fromBalance: fromWallet.balance,
            toBalance: toWallet.balance
        };
    }

    // Obtener balance
    obtenerBalance(address) {
        const wallet = this.wallets.get(address);
        if (!wallet) {
            throw new Error('Wallet no encontrado');
        }

        console.log(`💰 Balance de ${wallet.nombreUsuario}: ${wallet.balance} ETH`);
        return wallet.balance;
    }
}

// Ejemplo de uso del sistema de pagos
function ejemploSistemaPagos() {
    const sistema = new SistemaPagos();

    try {
        // Crear wallets
        const aliceWallet = sistema.crearWallet('Alice');
        const bobWallet = sistema.crearWallet('Bob');

        // Añadir balance inicial (simulado)
        aliceWallet.balance = 10.0;
        bobWallet.balance = 5.0;

        console.log('\n💰 Balances iniciales:');
        sistema.obtenerBalance(aliceWallet.address);
        sistema.obtenerBalance(bobWallet.address);

        // Crear transacción
        const transaccion = sistema.crearTransaccion(aliceWallet.address, bobWallet.address, 2.5);

        // Procesar transacción
        const resultado = sistema.procesarTransaccion(0);

        console.log('\n💰 Balances finales:');
        sistema.obtenerBalance(aliceWallet.address);
        sistema.obtenerBalance(bobWallet.address);

    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// ==================== EJEMPLO 3: API DE SEGURIDAD ====================

console.log('\n🔒 API DE SEGURIDAD');
console.log('='.repeat(60));

class APISeguridad {
    constructor() {
        this.sesiones = new Map();
        this.intentosLogin = new Map();
    }

    // Generar token de sesión
    generarTokenSesion(username) {
        const token = cryptoLib.generateRandomString(32);
        const sesion = {
            username,
            token,
            fechaCreacion: new Date(),
            activa: true,
            ultimaActividad: new Date()
        };

        this.sesiones.set(token, sesion);
        console.log(`🎫 Token de sesión generado para ${username}`);
        return token;
    }

    // Verificar token
    verificarToken(token) {
        const sesion = this.sesiones.get(token);
        if (!sesion || !sesion.activa) {
            return false;
        }

        // Actualizar última actividad
        sesion.ultimaActividad = new Date();
        return true;
    }

    // Cerrar sesión
    cerrarSesion(token) {
        const sesion = this.sesiones.get(token);
        if (sesion) {
            sesion.activa = false;
            console.log(`🚪 Sesión cerrada para ${sesion.username}`);
        }
    }

    // Generar API key
    generarAPIKey(nombreServicio) {
        const apiKey = cryptoLib.generateRandomString(48);
        const hashAPIKey = cryptoLib.sha256(apiKey);
        
        const apiKeyInfo = {
            nombreServicio,
            hash: hashAPIKey,
            fechaCreacion: new Date(),
            activa: true,
            ultimoUso: null
        };

        console.log(`🔑 API Key generada para ${nombreServicio}`);
        console.log(`   Key: ${apiKey}`);
        console.log(`   Hash: ${hashAPIKey}`);

        return { apiKey, hash: hashAPIKey };
    }

    // Verificar API key
    verificarAPIKey(apiKey, hashEsperado) {
        const hashCalculado = cryptoLib.sha256(apiKey);
        const esValida = hashCalculado === hashEsperado;

        if (esValida) {
            console.log(`✅ API Key válida`);
        } else {
            console.log(`❌ API Key inválida`);
        }

        return esValida;
    }

    // Cifrar datos sensibles
    cifrarDatosSensibles(datos, password) {
        const datosString = JSON.stringify(datos);
        const datosCifrados = cryptoLib.encryptAESAdvanced(datosString, password);
        const hashDatos = cryptoLib.sha256(datosString);

        console.log(`🔐 Datos cifrados exitosamente`);
        console.log(`   Hash original: ${hashDatos}`);

        return {
            datosCifrados,
            hashOriginal: hashDatos
        };
    }

    // Descifrar datos sensibles
    descifrarDatosSensibles(datosCifrados, password, hashOriginal) {
        try {
            const datosDescifrados = cryptoLib.decryptAESAdvanced(datosCifrados, password);
            const hashVerificado = cryptoLib.sha256(datosDescifrados);
            const integridadVerificada = hashVerificado === hashOriginal;

            if (!integridadVerificada) {
                throw new Error('Integridad de datos comprometida');
            }

            const datos = JSON.parse(datosDescifrados);
            console.log(`🔓 Datos descifrados exitosamente`);
            console.log(`   Integridad: ${integridadVerificada ? '✅ Verificada' : '❌ Comprometida'}`);

            return { datos, integridadVerificada };
        } catch (error) {
            throw new Error('Error al descifrar datos: ' + error.message);
        }
    }
}

// Ejemplo de uso de la API de seguridad
function ejemploAPISeguridad() {
    const api = new APISeguridad();

    try {
        // Generar token de sesión
        const token = api.generarTokenSesion('usuario123');
        
        // Verificar token
        const esValida = api.verificarToken(token);
        console.log(`Token válido: ${esValida ? '✅ Sí' : '❌ No'}`);

        // Generar API key
        const { apiKey, hash } = api.generarAPIKey('MiServicio');
        
        // Verificar API key
        api.verificarAPIKey(apiKey, hash);

        // Cifrar datos sensibles
        const datosSensibles = {
            tarjetaCredito: '1234-5678-9012-3456',
            cvv: '123',
            fechaVencimiento: '12/25'
        };

        const { datosCifrados, hashOriginal } = api.cifrarDatosSensibles(datosSensibles, 'miPassword123');
        
        // Descifrar datos sensibles
        const { datos, integridadVerificada } = api.descifrarDatosSensibles(datosCifrados, 'miPassword123', hashOriginal);
        
        console.log(`Datos descifrados:`, datos);

        // Cerrar sesión
        api.cerrarSesion(token);

    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// ==================== EJECUTAR TODOS LOS EJEMPLOS ====================

async function ejecutarEjemplos() {
    console.log('🚀 Ejecutando ejemplos de librería específica...\n');
    
    await ejemploGestorDocumentos();
    ejemploSistemaPagos();
    ejemploAPISeguridad();
    
    console.log('\n🎉 ¡Todos los ejemplos de librería específica ejecutados exitosamente! 🎉');
}

// Ejecutar ejemplos
ejecutarEjemplos();
