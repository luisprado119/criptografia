/**
 * Ejemplos Prácticos de la Librería Criptográfica
 * Este archivo contiene ejemplos ejecutables de todas las funcionalidades
 */

const cryptoLib = require('../src/index');
const fs = require('fs');

console.log('🔐 EJEMPLOS PRÁCTICOS DE LA LIBRERÍA CRIPTOGRÁFICA 🔐\n');

// ==================== EJEMPLO 1: SISTEMA DE AUTENTICACIÓN ====================

console.log('1️⃣ SISTEMA DE AUTENTICACIÓN BÁSICO');
console.log('='.repeat(50));

function registrarUsuario(username, password) {
    const { hash, salt } = cryptoLib.hashPassword(password);

    const usuario = {
        username: username,
        passwordHash: hash,
        salt: salt,
        fechaRegistro: new Date()
    };

    console.log(`Usuario registrado: ${username}`);
    return usuario;
}

function loginUsuario(username, password, usuarioGuardado) {
    const isValid = cryptoLib.verifyPassword(password, usuarioGuardado.passwordHash, usuarioGuardado.salt);

    if (isValid) {
        console.log(`✅ Login exitoso para ${username}`);
        return true;
    } else {
        console.log(`❌ Contraseña incorrecta para ${username}`);
        return false;
    }
}

// Ejemplo de uso
const usuario = registrarUsuario('admin', 'miPassword123');
loginUsuario('admin', 'miPassword123', usuario);
loginUsuario('admin', 'passwordIncorrecta', usuario);
console.log();

// ==================== EJEMPLO 2: CIFRADO DE DOCUMENTOS ====================

console.log('2️⃣ CIFRADO DE DOCUMENTOS SENSIBLES');
console.log('='.repeat(50));

async function cifrarDocumento(archivoOriginal, archivoCifrado, password) {
    try {
        const hashOriginal = await cryptoLib.hashFile(archivoOriginal, 'sha256');
        console.log('Hash original:', hashOriginal);

        const resultado = await cryptoLib.encryptFile(archivoOriginal, archivoCifrado, password);
        console.log('Archivo cifrado exitosamente');

        return { hashOriginal, resultado };
    } catch (error) {
        console.error('Error al cifrar:', error.message);
    }
}

async function descifrarDocumento(archivoCifrado, archivoDescifrado, password, hashOriginal) {
    try {
        const resultado = await cryptoLib.decryptFile(archivoCifrado, archivoDescifrado, password);
        console.log('Archivo descifrado exitosamente');

        const hashDescifrado = await cryptoLib.hashFile(archivoDescifrado, 'sha256');
        const integridadVerificada = hashOriginal === hashDescifrado;

        console.log('Integridad verificada:', integridadVerificada ? '✅ Sí' : '❌ No');

        return { resultado, integridadVerificada };
    } catch (error) {
        console.error('Error al descifrar:', error.message);
    }
}

async function ejemploCifrado() {
    const password = 'miPasswordSuperSecreta123';

    // Crear archivo de prueba
    fs.writeFileSync('documento.txt', 'Este es un documento confidencial');

    // Cifrar
    const { hashOriginal } = await cifrarDocumento('documento.txt', 'documento.enc', password);

    // Descifrar
    await descifrarDocumento('documento.enc', 'documento-descifrado.txt', password, hashOriginal);

    // Limpiar archivos
    ['documento.txt', 'documento.enc', 'documento-descifrado.txt'].forEach(archivo => {
        if (fs.existsSync(archivo)) fs.unlinkSync(archivo);
    });
}

ejemploCifrado().then(() => {
    console.log();

    // ==================== EJEMPLO 3: WALLET ETHEREUM ====================

    console.log('3️⃣ WALLET ETHEREUM SIMPLE');
    console.log('='.repeat(50));

    function crearWalletEthereum() {
        const keyPair = cryptoLib.generateSecp256k1KeyPair();
        const address = cryptoLib.getEthereumAddress(keyPair.publicKey);

        return {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            address: address
        };
    }

    function firmarTransaccion(transaccion, privateKey) {
        const transaccionString = JSON.stringify(transaccion);
        const hashTransaccion = cryptoLib.keccak256(transaccionString);

        const signature = cryptoLib.signSecp256k1(hashTransaccion, privateKey);

        return {
            transaccion: transaccion,
            hash: hashTransaccion,
            signature: signature.signature,
            recoveryId: signature.recoveryId
        };
    }

    // Crear wallet
    const wallet = crearWalletEthereum();
    console.log('Wallet creado:');
    console.log('Dirección:', wallet.address);
    console.log('Clave privada:', wallet.privateKey.substring(0, 20) + '...');

    // Crear transacción
    const transaccion = {
        from: wallet.address,
        to: '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
        value: '1000000000000000000', // 1 ETH en wei
        gas: '21000',
        gasPrice: '20000000000', // 20 gwei
        nonce: 0
    };

    // Firmar transacción
    const transaccionFirmada = firmarTransaccion(transaccion, wallet.privateKey);
    console.log('\nTransacción firmada:');
    console.log('Hash:', transaccionFirmada.hash);
    console.log('Firma:', transaccionFirmada.signature.substring(0, 20) + '...');
    console.log();

    // ==================== EJEMPLO 4: MENSAJERÍA SEGURA ====================

    console.log('4️⃣ SISTEMA DE MENSAJERÍA SEGURA');
    console.log('='.repeat(50));

    function generarParClaves() {
        return cryptoLib.generateRSAKeyPair(2048);
    }

    function enviarMensaje(mensaje, clavePublicaDestinatario) {
        const mensajeCifrado = cryptoLib.encryptRSA(mensaje, clavePublicaDestinatario);
        const hashMensaje = cryptoLib.sha256(mensaje);

        return {
            mensajeCifrado: mensajeCifrado,
            hash: hashMensaje,
            timestamp: new Date().toISOString()
        };
    }

    function recibirMensaje(mensajeEnviado, clavePrivadaDestinatario) {
        try {
            const mensajeDescifrado = cryptoLib.decryptRSA(mensajeEnviado.mensajeCifrado, clavePrivadaDestinatario);
            const hashVerificado = cryptoLib.sha256(mensajeDescifrado);

            const integridadVerificada = hashVerificado === mensajeEnviado.hash;

            return {
                mensaje: mensajeDescifrado,
                integridadVerificada: integridadVerificada,
                timestamp: mensajeEnviado.timestamp
            };
        } catch (error) {
            return {
                error: 'No se pudo descifrar el mensaje',
                integridadVerificada: false
            };
        }
    }

    // Generar claves para Alice y Bob
    const aliceKeys = generarParClaves();
    const bobKeys = generarParClaves();

    console.log('Claves generadas para Alice y Bob');

    // Alice envía mensaje a Bob
    const mensajeOriginal = 'Hola Bob, este es un mensaje secreto!';
    const mensajeEnviado = enviarMensaje(mensajeOriginal, bobKeys.publicKey);

    console.log('\nMensaje enviado por Alice:');
    console.log('Mensaje cifrado:', mensajeEnviado.mensajeCifrado.substring(0, 50) + '...');
    console.log('Hash:', mensajeEnviado.hash);

    // Bob recibe y descifra el mensaje
    const mensajeRecibido = recibirMensaje(mensajeEnviado, bobKeys.privateKey);

    console.log('\nMensaje recibido por Bob:');
    console.log('Mensaje:', mensajeRecibido.mensaje);
    console.log('Integridad verificada:', mensajeRecibido.integridadVerificada ? '✅ Sí' : '❌ No');
    console.log();

    // ==================== EJEMPLO 5: VERIFICACIÓN DE INTEGRIDAD ====================

    console.log('5️⃣ VERIFICACIÓN DE INTEGRIDAD DE ARCHIVOS');
    console.log('='.repeat(50));

    async function crearArchivoConHash(contenido, nombreArchivo) {
        fs.writeFileSync(nombreArchivo, contenido);
        const hash = await cryptoLib.hashFile(nombreArchivo, 'sha256');

        fs.writeFileSync(nombreArchivo + '.hash', hash);

        console.log(`Archivo creado: ${nombreArchivo}`);
        console.log(`Hash guardado: ${hash}`);

        return hash;
    }

    async function verificarIntegridad(nombreArchivo) {
        try {
            const hashGuardado = fs.readFileSync(nombreArchivo + '.hash', 'utf8');
            const hashActual = await cryptoLib.hashFile(nombreArchivo, 'sha256');

            const integridadVerificada = hashGuardado === hashActual;

            console.log(`\nVerificación de integridad para ${nombreArchivo}:`);
            console.log('Hash guardado:', hashGuardado);
            console.log('Hash actual:', hashActual);
            console.log('Integridad:', integridadVerificada ? '✅ Archivo íntegro' : '❌ Archivo modificado');

            return integridadVerificada;
        } catch (error) {
            console.error('Error al verificar integridad:', error.message);
            return false;
        }
    }

    async function ejemploIntegridad() {
        const contenido = 'Este es un archivo importante que no debe ser modificado.';
        const nombreArchivo = 'archivo-importante.txt';

        // Crear archivo con hash
        await crearArchivoConHash(contenido, nombreArchivo);

        // Verificar integridad (debería ser válida)
        await verificarIntegridad(nombreArchivo);

        // Modificar archivo
        fs.appendFileSync(nombreArchivo, ' - MODIFICADO');
        console.log('\n--- Archivo modificado ---');

        // Verificar integridad (debería fallar)
        await verificarIntegridad(nombreArchivo);

        // Limpiar archivos
        [nombreArchivo, nombreArchivo + '.hash'].forEach(archivo => {
            if (fs.existsSync(archivo)) fs.unlinkSync(archivo);
        });
    }

    ejemploIntegridad().then(() => {
        console.log();

        // ==================== EJEMPLO 6: COMPARACIÓN DE ALGORITMOS ====================

        console.log('6️⃣ COMPARACIÓN DE ALGORITMOS DE HASH');
        console.log('='.repeat(50));

        function compararAlgoritmosHash(texto) {
            console.log(`Comparando algoritmos de hash para: "${texto}"\n`);

            const algoritmos = [
                { nombre: 'SHA-256', funcion: cryptoLib.sha256 },
                { nombre: 'MD5', funcion: cryptoLib.md5 },
                { nombre: 'SHA-1', funcion: cryptoLib.sha1 },
                { nombre: 'Keccak-256', funcion: cryptoLib.keccak256 }
            ];

            algoritmos.forEach(algoritmo => {
                const inicio = Date.now();
                const hash = algoritmo.funcion(texto);
                const tiempo = Date.now() - inicio;

                console.log(`${algoritmo.nombre}:`);
                console.log(`  Hash: ${hash}`);
                console.log(`  Longitud: ${hash.length} caracteres`);
                console.log(`  Tiempo: ${tiempo}ms\n`);
            });
        }

        const texto = 'Hola mundo criptográfico!';
        compararAlgoritmosHash(texto);

        // ==================== EJEMPLO 7: GENERADOR DE CONTRASEÑAS ====================

        console.log('7️⃣ GENERADOR DE CONTRASEÑAS SEGURAS');
        console.log('='.repeat(50));

        function generarContraseñaSegura(longitud = 16, incluirSimbolos = true) {
            const caracteres = {
                minusculas: 'abcdefghijklmnopqrstuvwxyz',
                mayusculas: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                numeros: '0123456789',
                simbolos: '!@#$%^&*()_+-=[]{}|;:,.<>?'
            };

            let pool = caracteres.minusculas + caracteres.mayusculas + caracteres.numeros;
            if (incluirSimbolos) {
                pool += caracteres.simbolos;
            }

            let contraseña = '';
            for (let i = 0; i < longitud; i++) {
                const randomIndex = Math.floor(Math.random() * pool.length);
                contraseña += pool[randomIndex];
            }

            return contraseña;
        }

        function evaluarSeguridadContraseña(contraseña) {
            const { hash, salt } = cryptoLib.hashPassword(contraseña);

            return {
                contraseña: contraseña,
                hash: hash,
                salt: salt,
                longitud: contraseña.length,
                segura: contraseña.length >= 12 && /[A-Z]/.test(contraseña) && /[a-z]/.test(contraseña) && /[0-9]/.test(contraseña)
            };
        }

        console.log('=== Generador de Contraseñas Seguras ===\n');

        const contraseñas = [
            generarContraseñaSegura(8, false),   // Contraseña débil
            generarContraseñaSegura(12, true),   // Contraseña media
            generarContraseñaSegura(16, true),   // Contraseña fuerte
            generarContraseñaSegura(20, true)    // Contraseña muy fuerte
        ];

        contraseñas.forEach((contraseña, index) => {
            console.log(`Contraseña ${index + 1}: ${contraseña}`);
            const evaluacion = evaluarSeguridadContraseña(contraseña);
            console.log(`Segura: ${evaluacion.segura ? '✅ Sí' : '❌ No'}`);
            console.log(`Longitud: ${evaluacion.longitud} caracteres\n`);
        });

        console.log('🎉 ¡Todos los ejemplos ejecutados exitosamente! 🎉');
    });
});
